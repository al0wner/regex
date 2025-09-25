// vim: syntax=P4
/*
    HalfSipHash-2-4 Ingress+Egress

    Copyright (C) 2021 Sophia Yoo & Xiaoqi Chen, Princeton University
    sophiayoo [at] princeton.edu

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.
    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

// supported input lengths: 2~8 words.
#ifndef NUM_WORDS
    #define NUM_WORDS 4
    #define NUM_WORDS_IG 2
    #define NUM_WORDS_EG 2
#endif
#if !((NUM_WORDS_IG+NUM_WORDS_EG==NUM_WORDS) && (NUM_WORDS_IG-NUM_WORDS_EG==0 || NUM_WORDS_IG-NUM_WORDS_EG==1 ))
	#error "Please set NUM_WORDS_IG to be floor((NUM_WORDS+1)/2) and NUM_WORDS_EG to be floor((NUM_WORDS)/2)."
#endif

#define SIP_PORT 5555
#define SIP_KEY_0 0x33323130
#define SIP_KEY_1 0x42413938

// validation stuff
#define SVF_LENGTH 32
#define REVF_LENGTH 32
#define KEY_LENGTH 32
#define TRANS_ID_BITS 32
#define DFA_STATE_BITS 8
#define DATAHASH_LENGTH 32
#define TRANS_LENGTH 32
#define MAX_REVF_LENGTH 8  // need to cut parse bytes
#define MAX_PATH_LENGTH 8
#define TIMESTAMP_LENGTH 48
#define REVF_INPUT_LENGTH 120

const bit<32> const_0 = 0;
const bit<32> const_1 = 0;
const bit<32> const_2 = 0x6c796765;
const bit<32> const_3 = 0x74656462;

#define ROUND_TYPE_COMPRESSION 0
#define ROUND_TYPE_FINALIZATION 1
#define ROUND_TYPE_END 2

#include "loops_macro.h"

#include <core.p4>
#include <tna.p4>

typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;
typedef bit<16> ether_type_t;
const ether_type_t ETHERTYPE_IPV4 = 16w0x0800;
const ether_type_t ETHERTYPE_VLAN = 16w0x0810;

typedef bit<8> ip_protocol_t;
const ip_protocol_t IP_PROTOCOLS_ICMP = 1;
const ip_protocol_t IP_PROTOCOLS_TCP = 6;
const ip_protocol_t IP_PROTOCOLS_UDP = 17;

header whattodo_h {
	bit<8> case_num; // within 7
}

header hashstage_h {
	bit<8> stage_num; // within 7
}

header revf_t {
    bit<REVF_LENGTH> revf;
}

header path_t {
    bit<TRANS_ID_BITS> transition_id;
}

header path_meta_t {
    bit<8> path_length;
}

header validation_h {
    bit<8> dfa_id;
    bit<DFA_STATE_BITS> dfa_state;
    bit<8> revf_length;
    bit<DATAHASH_LENGTH> datahash;
    bit<SVF_LENGTH> svf;
    
}

header ethernet_h {
	mac_addr_t dst_addr;
	mac_addr_t src_addr;
	bit<16> ether_type;
}

header ipv4_h {
	bit<4> version;
	bit<4> ihl;
	bit<8> diffserv;
	bit<16> total_len;
	bit<16> identification;
	bit<3> flags;
	bit<13> frag_offset;
	bit<8> ttl;
	bit<8> protocol;
	bit<16> hdr_checksum;
	ipv4_addr_t src_addr;
	ipv4_addr_t dst_addr;
}

header tcp_h {
	bit<16> src_port;
	bit<16> dst_port;
	bit<32> seq_no;
	bit<32> ack_no;
	bit<4> data_offset;
	bit<4> res;
	bit<8> flags;
	bit<16> window;
	bit<16> checksum;
	bit<16> urgent_ptr;
}

header udp_h {
	bit<16> src_port;
	bit<16> dst_port;
	bit<16> udp_total_len;
	bit<16> checksum;
}

header sip_inout_h {
	#define vardef_m(i) bit<32> m_##i;
	__LOOP(NUM_WORDS, vardef_m)
}

header sip_meta_h {
	bit<32> v_0;
	bit<32> v_1;
	bit<32> v_2;
	bit<32> v_3;
	bit<16> dest_port;
	bit<8> curr_round;
}

struct header_t {
// apparently order of headers doesn't matter if they are read correctly...
	ethernet_h ethernet;
	sip_inout_h sip;
	sip_meta_h sip_meta;
	whattodo_h whattodo;
	hashstage_h hash_stage;
	ipv4_h ipv4;
	validation_h validation;
    revf_t[MAX_REVF_LENGTH] revfs;
    path_meta_t pathmeta;
    path_t[MAX_PATH_LENGTH] path;
	tcp_h tcp;
	udp_h udp;    
}

header sip_tmp_h {
	bit<32> a_0;
	bit<32> a_1;
	bit<32> a_2;
	bit<32> a_3;
	bit<32> i_0;
	bit<32> i_1;
	bit<32> i_2;
	bit<32> i_3;
	bit<8> round_type;
}

struct ig_metadata_t {
	bool recirc;
	bit<9> rnd_port_for_recirc;
	bit<1> rnd_bit;
	bit<5> pad;
	sip_tmp_h sip_tmp;
	bit<KEY_LENGTH> key;
    bit<REVF_LENGTH> revf_prime;
    bit<TRANS_ID_BITS> trans_id;
    bit<8> revf_remaining;
    bit<8> path_remaining;
}

struct eg_metadata_t {
	sip_tmp_h sip_tmp;
	bit<KEY_LENGTH> key;
    bit<REVF_LENGTH> revf_prime;
    bit<TRANS_ID_BITS> trans_id;
    bit<8> revf_remaining;
    bit<8> path_remaining;
}

parser TofinoIngressParser(
		packet_in pkt,
		inout ig_metadata_t ig_md,
		out ingress_intrinsic_metadata_t ig_intr_md) {
	state start {
		pkt.extract(ig_intr_md);
		transition select(ig_intr_md.resubmit_flag) {
			1 : parse_resubmit;
			0 : parse_port_metadata;
		}
	}

	state parse_resubmit {
		// Parse resubmitted packet here.
		pkt.advance(64);
		transition accept;
	}

	state parse_port_metadata {
		pkt.advance(64);  //tofino 1 port metadata size
		transition accept;
	}
}
parser SwitchIngressParser(
		packet_in pkt,
		out header_t hdr,
		out ig_metadata_t ig_md,
		out ingress_intrinsic_metadata_t ig_intr_md) {

	TofinoIngressParser() tofino_parser;

	state start {
		tofino_parser.apply(pkt, ig_md, ig_intr_md);
		transition parse_ethernet;
	}

	state parse_ethernet {
		pkt.extract(hdr.ethernet);
		transition select (hdr.ethernet.ether_type) {
			ETHERTYPE_IPV4 : parse_ipv4;
			default : reject;
		}
	}

	state parse_sip_and_meta_maybe { 
	// this is a catch all reached after parse_validation is completed 
	// Because you can't nest transition select{...}. So the parser comes here and then branches out again.
	
	transition select(hdr.udp.dst_port) {
			SIP_PORT+1: parse_notfirstpass; // after first step but not recirc
			SIP_PORT+2: parse_recirc; // recirc
			default: accept;
		}
	}
	
	state parse_notfirstpass {
	        pkt.extract(hdr.whattodo);
	        transition select(hdr.whattodo.case_num) {
                2: parse_sip;
                3: parse_hashstage_and_sip;
                default: accept;
            }
		
	}
	
	state parse_sip{
	        pkt.advance(8); // skip over hash_stage
	        pkt.extract(hdr.sip);
		transition accept;
	}
	
	state parse_hashstage_and_sip{
	        pkt.extract(hdr.hash_stage);
	        pkt.extract(hdr.sip);
	        transition accept;
	}
	
	state parse_recirc{
	        pkt.extract(hdr.whattodo);
	        pkt.advance(8); // skip over hash_stage
	        pkt.extract(hdr.sip);
		pkt.extract(hdr.sip_meta);
		transition accept;
	}
        
        // for validation, revf_length and path_length are assumed to be max 2. Increase if needed...
        state parse_validation {
        pkt.extract(hdr.validation);
        ig_md.revf_remaining = hdr.validation.revf_length;
        transition select(ig_md.revf_remaining) {
            0: parse_path_meta;
            1: parse_revf_0;
            2: parse_revf_0;
            default: parse_path_meta; // can't parse if greater length. Go to the next step
        }
    }

    state parse_revf_0 {
        pkt.extract(hdr.revfs[0]);
        transition select(ig_md.revf_remaining) {
            1: parse_path_meta;
            2: parse_revf_1;
        }
    }

    
    state parse_revf_1 {
        pkt.extract(hdr.revfs[1]);
        transition parse_path_meta;
    }

    state parse_path_meta {
        pkt.extract(hdr.pathmeta);
        ig_md.path_remaining = hdr.pathmeta.path_length;
        transition select(ig_md.path_remaining) {
            0: parse_sip_and_meta_maybe;
            1: parse_path_0;
            2: parse_path_0;
            default: parse_sip_and_meta_maybe; // can't parse if greater length. Go to the next step
        }
    }

    
    state parse_path_0 {
        pkt.extract(hdr.path[0]);
        transition select(ig_md.path_remaining) {
            1: parse_sip_and_meta_maybe;
            2: parse_path_1;
        }
    }

    
    state parse_path_1 {
        pkt.extract(hdr.path[1]);
        transition parse_sip_and_meta_maybe;
    }

	state parse_ipv4 {
		pkt.extract(hdr.ipv4);
		transition select(hdr.ipv4.protocol) {
			IP_PROTOCOLS_TCP : parse_tcp;
			IP_PROTOCOLS_UDP : parse_udp;
			default : accept;
		}
	}

	state parse_tcp {
		pkt.extract(hdr.tcp);
		transition select(hdr.ipv4.total_len) {
			default : accept;
		}
	}
        
        // udp leads to validation etc.
	state parse_udp { 
		pkt.extract(hdr.udp);
		transition select(hdr.udp.dst_port){
		
		SIP_PORT: parse_validation; // packet just came in, parse validation
		SIP_PORT+1: parse_validation; // packet is doing next steps but not recirc, parse validation
		SIP_PORT+2: parse_validation; // packet is doing recirc, parse validation
		default: accept; // otherwise not relevant for validation etc.
	    }
	}
}

control SwitchIngressDeparser(
		packet_out pkt,
		inout header_t hdr,
		in ig_metadata_t ig_md,
		in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md) {
	apply {
		pkt.emit(hdr.ethernet);
		pkt.emit(hdr.ipv4);
		pkt.emit(hdr.tcp);
		pkt.emit(hdr.udp);
		pkt.emit(hdr.validation);
		pkt.emit(hdr.revfs);
                pkt.emit(hdr.pathmeta);
                pkt.emit(hdr.path);
                pkt.emit(hdr.whattodo);
                pkt.emit(hdr.hash_stage);
		pkt.emit(hdr.sip);
		pkt.emit(hdr.sip_meta);
	}
}

parser TofinoEgressParser(
		packet_in pkt,
		inout egress_intrinsic_metadata_t eg_intr_md) {

	state start {
		pkt.extract(eg_intr_md);
		transition accept;
	}
}
parser SwitchEgressParser(
		packet_in pkt,
		out header_t hdr,
		out eg_metadata_t eg_md,
		out egress_intrinsic_metadata_t eg_intr_md) {

	TofinoEgressParser() tofino_parser;

	state start {
		tofino_parser.apply(pkt, eg_intr_md);
		transition parse_ethernet;
	}

	state parse_ethernet {
		pkt.extract(hdr.ethernet);
		transition select (hdr.ethernet.ether_type) {
			ETHERTYPE_IPV4 : parse_ipv4;
			default : reject;
		}
	}

	state parse_sip_and_meta_maybe { 
	// this is a catch all reached after parse_validation is completed 
	// Because you can't nest transition select{...}. So the parser comes here and then branches out again.
	
	transition select(hdr.udp.dst_port) {
			SIP_PORT+1: parse_notfirstpass; // after first step but not recirc
			SIP_PORT+2: parse_recirc; // recirc
			default: accept;
		}
	}
	
	state parse_notfirstpass {
	        pkt.extract(hdr.whattodo);
	        transition select(hdr.whattodo.case_num) {
                2: parse_sip;
                3: parse_hashstage_and_sip;
                default: accept;
            }
		
	}
	
	state parse_sip{
	        pkt.advance(8); // skip over hash_stage
	        pkt.extract(hdr.sip);
		transition accept;
	}
	
	state parse_hashstage_and_sip{
	        pkt.extract(hdr.hash_stage);
	        pkt.extract(hdr.sip);
	        transition accept;
	}
	
	state parse_recirc{
	        pkt.extract(hdr.whattodo);
	        pkt.advance(8); // skip over hash_stage
	        pkt.extract(hdr.sip);
		pkt.extract(hdr.sip_meta);
		transition accept;
	}
	
        
        state parse_validation {
        pkt.extract(hdr.validation);
        eg_md.revf_remaining = hdr.validation.revf_length;
        transition select(eg_md.revf_remaining) {
            0: parse_path_meta;
            1: parse_revf_0;
            2: parse_revf_0;
            default: parse_path_meta; // can't parse if greater length. Go to the next step
        }
    }

    
    state parse_revf_0 {
        pkt.extract(hdr.revfs[0]);
        transition select(eg_md.revf_remaining) {
            1: parse_path_meta;
            2: parse_revf_1;
        }
    }

    
    state parse_revf_1 {
        pkt.extract(hdr.revfs[1]);
        transition parse_path_meta;
    }

    state parse_path_meta {
        pkt.extract(hdr.pathmeta);
        eg_md.path_remaining = hdr.pathmeta.path_length;
        transition select(eg_md.path_remaining) {
            0: parse_sip_and_meta_maybe;
            1: parse_path_0;
            2: parse_path_0;
            default: parse_sip_and_meta_maybe; // can't parse if greater length. Go to the next step
        }
    }

    
    state parse_path_0 {
        pkt.extract(hdr.path[0]);
        transition select(eg_md.path_remaining) {
            1: parse_sip_and_meta_maybe;
            2: parse_path_1;
        }
    }

    
    state parse_path_1 {
        pkt.extract(hdr.path[1]);
        transition accept;
    }


	state parse_ipv4 {
		pkt.extract(hdr.ipv4);
		transition select(hdr.ipv4.protocol) {
			IP_PROTOCOLS_TCP : parse_tcp;
			IP_PROTOCOLS_UDP : parse_udp;
			default : accept;
		}
	}

	state parse_tcp {
		pkt.extract(hdr.tcp);
		transition select(hdr.ipv4.total_len) {
			default : accept;
		}
	}

	state parse_udp {
		pkt.extract(hdr.udp);
		transition select(hdr.udp.dst_port){
		
		SIP_PORT: parse_validation; // packet just came in, parse validation
		SIP_PORT+1: parse_validation; // packet is doing next steps but not recirc, parse validation
		SIP_PORT+2: parse_validation; // packet is doing recirc, parse validation
		default: accept; // otherwise not relevant for validation etc.
	}
    }
}

control SwitchEgressDeparser(
		packet_out pkt,
		inout header_t hdr,
		in eg_metadata_t eg_md,
		in egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr) {
	apply {
		pkt.emit(hdr.ethernet);
		pkt.emit(hdr.ipv4);
		pkt.emit(hdr.tcp);
		pkt.emit(hdr.udp);
		pkt.emit(hdr.validation);
		pkt.emit(hdr.revfs);
                pkt.emit(hdr.pathmeta);
                pkt.emit(hdr.path);
                pkt.emit(hdr.whattodo);
                pkt.emit(hdr.hash_stage);
		pkt.emit(hdr.sip);
		pkt.emit(hdr.sip_meta);
		
		
	}
}


control SwitchIngress(
		inout header_t hdr,
		inout ig_metadata_t ig_md,
		in ingress_intrinsic_metadata_t ig_intr_md,
		in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
		inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
		inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {

	action drop(){
		ig_intr_dprsr_md.drop_ctl = 0x1; // Drop packet.
	}

	action nop() {
	}
	
	// DFA actions and tables
	
	action dfa_transition(bit<DFA_STATE_BITS> state, bit<TRANS_ID_BITS> transition_id) {
            hdr.validation.dfa_state = state;
            ig_md.trans_id = transition_id;
        }
    
        table dfa_trans {
            key = {
                hdr.validation.dfa_id: exact;
                hdr.validation.dfa_state: exact;
            }
            actions = {
                dfa_transition;
                NoAction;
            }
            size = 512;
            default_action = NoAction();
        }
        
        
    
	
	// ok DFA actions and tables over

	action routing_decision(){
		//packet routing: for now we simply bounce back the packet.
		//any routing match-action logic should be added here.
		
		hdr.sip_meta.dest_port=(bit<16>) ig_intr_md.ingress_port+1; // it leaves from wherever it entered (0 now) + 1
	}

	action route_to(bit<9> port){
		ig_intr_tm_md.ucast_egress_port=port;
	}

	//select one of two ports for recirculation
	Random< bit<1> >() rng;

	action get_rnd_bit(){
		ig_md.rnd_bit = rng.get();
		//ig_md.rnd_bit = ig_intr_md.ingress_mac_tstamp[0:0];
	}

	action do_recirculate(){
		route_to(ig_md.rnd_port_for_recirc);
	}

	action incr_and_recirc(bit<8> next_round){
		hdr.sip_meta.curr_round = next_round;
		do_recirculate();
		//hdr.sip_meta.setValid();
		hdr.udp.dst_port=SIP_PORT+2;
	}

	action do_not_recirc_end_in_ig(){
		route_to((bit<9>)hdr.sip_meta.dest_port);
		hdr.udp.dst_port=SIP_PORT+1; 
		#define ig_writeout_m(i) hdr.sip.m_##i = 0;
		__LOOP(NUM_WORDS,ig_writeout_m)
		@in_hash { hdr.sip.m_0 = hdr.sip_meta.v_1 ^ hdr.sip_meta.v_3; }
		hdr.sip_meta.setInvalid();
	}

	action do_not_recirc_end_in_eg(bit<8> next_round){
		route_to((bit<9>)hdr.sip_meta.dest_port);
		hdr.sip_meta.curr_round = next_round;
	}

	table tb_recirc_decision {
		key = {
			hdr.sip_meta.curr_round: exact;
		}
		actions = {
			incr_and_recirc;
			do_not_recirc_end_in_eg;
			do_not_recirc_end_in_ig;
			nop;
		}
		size = 32;
		default_action = nop;
		const entries = {
			// ingress performs round 0,4,8,...
			// even NUM_WORDS last round ends in egress, odd ends in ingress
			#define ig_rule_incr_m(i) (i*4): incr_and_recirc(i*4+2);
			#if (NUM_WORDS%2==0)
				__LOOP(NUM_WORDS_IG, ig_rule_incr_m)
				(NUM_WORDS*2): do_not_recirc_end_in_eg(NUM_WORDS*2+2);
			#else
				__LOOP(NUM_WORDS_IG, ig_rule_incr_m)
				(NUM_WORDS*2+2): do_not_recirc_end_in_ig();
			#endif
		}

	}
	action sip_init(bit<32> key_0, bit<32> key_1){
		hdr.sip_meta.v_0 = key_0 ^ const_0;
		hdr.sip_meta.v_1 = key_1 ^ const_1;
		hdr.sip_meta.v_2 = key_0 ^ const_2;
		hdr.sip_meta.v_3 = key_1 ^ const_3;
        }

        #define MSG_VAR_IG ig_md.sip_tmp.i_0
	action sip_1_odd(){
		//for first SipRound in set of <c> SipRounds
		//i_3 = i_3 ^ message
		hdr.sip_meta.v_3 = hdr.sip_meta.v_3 ^ MSG_VAR_IG;
	}
	action sip_1_a(){
		//a_0 = i_0 + i_1
		ig_md.sip_tmp.a_0 = hdr.sip_meta.v_0 + hdr.sip_meta.v_1;
		//a_2 = i_2 + i_3
		ig_md.sip_tmp.a_2 = hdr.sip_meta.v_2 + hdr.sip_meta.v_3;
		//a_1 = i_1 << 5
		@in_hash { ig_md.sip_tmp.a_1 = hdr.sip_meta.v_1[26:0] ++ hdr.sip_meta.v_1[31:27]; }
	}
	action sip_1_b(){
		//a_3 = i_3 << 8
		ig_md.sip_tmp.a_3 = hdr.sip_meta.v_3[23:0] ++ hdr.sip_meta.v_3[31:24];
	}
	action sip_2_a(){
		//b_1 = a_1 ^ a_0
		ig_md.sip_tmp.i_1 = ig_md.sip_tmp.a_1 ^ ig_md.sip_tmp.a_0;
		//b_3 = a_3 ^ a_2
		ig_md.sip_tmp.i_3 = ig_md.sip_tmp.a_3 ^ ig_md.sip_tmp.a_2;
		// b_0 = a_0 << 16
		ig_md.sip_tmp.i_0 = ig_md.sip_tmp.a_0[15:0] ++ ig_md.sip_tmp.a_0[31:16];
		//b_2 = a_2
		ig_md.sip_tmp.i_2 = ig_md.sip_tmp.a_2;
	}

	action sip_3_a(){
		//c_2 = b_2 + b_1
		ig_md.sip_tmp.a_2 = ig_md.sip_tmp.i_2 + ig_md.sip_tmp.i_1;
		//c_0 = b_0 + b_3
		ig_md.sip_tmp.a_0 = ig_md.sip_tmp.i_0 + ig_md.sip_tmp.i_3;
		//c_1 = b_1 << 13
		@in_hash { ig_md.sip_tmp.a_1 = ig_md.sip_tmp.i_1[18:0] ++ ig_md.sip_tmp.i_1[31:19]; }
	}
	action sip_3_b(){
		//c_3 = b_3 << 7
		@in_hash { ig_md.sip_tmp.a_3 = ig_md.sip_tmp.i_3[24:0] ++ ig_md.sip_tmp.i_3[31:25]; }
	}

	action sip_4_a(){
		//d_1 = c_1 ^ c_2
		hdr.sip_meta.v_1 = ig_md.sip_tmp.a_1 ^ ig_md.sip_tmp.a_2;
		//d_3 = c_3 ^ c_0 i
		hdr.sip_meta.v_3 = ig_md.sip_tmp.a_3 ^ ig_md.sip_tmp.a_0;
		//d_2 = c_2 << 16
		hdr.sip_meta.v_2 = ig_md.sip_tmp.a_2[15:0] ++ ig_md.sip_tmp.a_2[31:16];

	}
	action sip_4_b_odd(){
		//d_0 = c_0
		hdr.sip_meta.v_0 = ig_md.sip_tmp.a_0;
	}
	action sip_4_b_even(){
		//d_0 = c_0 ^ message
		hdr.sip_meta.v_0 = ig_md.sip_tmp.a_0 ^ MSG_VAR_IG;
	}

	//compression rounds
	// round 0~(2*NUM_WORDS-1)
	#define ig_def_start_m(i) action start_m_## i ##_compression(){\
		ig_md.sip_tmp.round_type = ROUND_TYPE_COMPRESSION;		\
		MSG_VAR_IG = hdr.sip.m_## i;								\
	}
	__LOOP(NUM_WORDS,ig_def_start_m)

	//round 2*NUM_WORDS (first 2 finalization rounds)
	action start_finalization_a(){
		ig_md.sip_tmp.round_type = ROUND_TYPE_FINALIZATION;
		MSG_VAR_IG = 0;
		// also xor v2 with FF at beginning of first finalization pass
		hdr.sip_meta.v_2 = hdr.sip_meta.v_2 ^ 32w0xff;
	}
	//round 2*NUM_WORDS+2 (last 2 finalization rounds)
	action start_finalization_b(){
		ig_md.sip_tmp.round_type = ROUND_TYPE_END;
		MSG_VAR_IG = 0;
	}

	table tb_start_round {
		key = {
			hdr.sip_meta.curr_round: exact;
		}
		size = 32;
		actions = {
			#define ig_actname_start_m_mul2(ix2) start_m_## ix2 ##_compression;
			#define ig_actname_start_m(i) __MUL(2,i, ig_actname_start_m_mul2)
			#if NUM_WORDS%2==0
				__LOOP(NUM_WORDS_IG, ig_actname_start_m)
				start_finalization_a;
			#else
				__LOOP(NUM_WORDS_IG, ig_actname_start_m)
				start_finalization_b;
			#endif
		}
		const entries = {
			#define ig_match_start_m_mul2(ix2) (ix2*2): start_m_## ix2 ##_compression();
			#define ig_match_start_m(i)  __MUL(2,i, ig_match_start_m_mul2)
			#if NUM_WORDS%2==0
				__LOOP(NUM_WORDS_IG, ig_match_start_m)
				(NUM_WORDS*2): start_finalization_a();
			#else
				__LOOP(NUM_WORDS_IG, ig_match_start_m)
				(NUM_WORDS*2+2): start_finalization_b();
			#endif
		}
	}

	#define ig_def_pre_end_m(i) action pre_end_m_## i ##_compression(){\
		MSG_VAR_IG = hdr.sip.m_## i;									\
	}
	__LOOP(NUM_WORDS,ig_def_pre_end_m)
	action pre_end_finalization_a(){
		MSG_VAR_IG = 0;
	}
	action pre_end_finalization_b(){
		MSG_VAR_IG = 0;
	}

	table tb_pre_end{
		key = {
			hdr.sip_meta.curr_round: exact;
		}
		size = 32;
		actions = {
			#define ig_actname_pre_end_m_mul2(ix2) pre_end_m_## ix2 ##_compression;
			#define ig_actname_pre_end_m(i) __MUL(2,i, ig_actname_pre_end_m_mul2)
			#if NUM_WORDS%2==0
				__LOOP(NUM_WORDS_IG, ig_actname_pre_end_m)
				pre_end_finalization_a;
			#else
				__LOOP(NUM_WORDS_IG, ig_actname_pre_end_m)
				pre_end_finalization_b;
			#endif
		}
		const entries = {
			#define ig_match_pre_end_m_mul2(ix2) (ix2*2): pre_end_m_## ix2 ##_compression();
			#define ig_match_pre_end_m(i) __MUL(2,i, ig_match_pre_end_m_mul2)
			#if NUM_WORDS%2==0
				__LOOP(NUM_WORDS_IG, ig_match_pre_end_m)
				(NUM_WORDS*2): pre_end_finalization_a();
			#else
				__LOOP(NUM_WORDS_IG, ig_match_pre_end_m)
				(NUM_WORDS*2+2): pre_end_finalization_b();
			#endif
		}
	}

	action start_first_pass(){
		//first pass init
	
		//hdr.sip.setValid();
		// set value of sip
		hdr.sip_meta.setValid();
		hdr.sip_meta.curr_round=0;

		sip_init(SIP_KEY_0, SIP_KEY_1);
		start_m_0_compression();

		routing_decision();
	}

	action set_m01() {
		hdr.sip.m_0 = hdr.validation.svf;
		hdr.sip.m_1 = hdr.validation.datahash;
	}
	action set_m2_1() {
		hdr.sip.m_2[31:27] = ig_md.trans_id[7:3];
	} 

	action set_m2_2() {
		hdr.sip.m_2[26:25] = ig_md.trans_id[2:1];
	}

	action set_m2_3() {
		hdr.sip.m_2[24:24] = ig_md.trans_id[0:0];
	}
	
	action set_m2_4() {
		hdr.sip.m_2[23:0] = 0;
	}
	action set_m3(){
		hdr.sip.m_3 = 0;
	}


	apply {
		  
		if (!hdr.whattodo.isValid()){
		    hdr.whattodo.setValid();
		    hdr.whattodo.case_num = 1;        
		}
		
		
		// start of the big if-else!!!
		if (hdr.whattodo.case_num == 1){
		// call DFA table
		    dfa_trans.apply();
		    //bit<56> padding = 0;
		    hdr.sip.setValid();
		    //bit<128> temp = hdr.validation.svf++hdr.validation.datahash++ig_md.trans_id++padding; //++ timestamp or whatever source sends
		    
		    // turn these into automated so that changing hash input length doesn't change these assignments
		    // hdr.sip.m_0 = temp[127:96];
			set_m01();
			set_m2_1();
			set_m2_2();
			set_m2_3();
			set_m2_4();
			set_m3();

			


		    hdr.hash_stage.setValid();
		    hdr.hash_stage.stage_num = 1;
		    hdr.udp.dst_port = SIP_PORT+1;
		    hdr.whattodo.case_num = 2;
	        }    
		    
		else if (hdr.whattodo.case_num == 2){
		    
		        //logic check for first pass
			if(!hdr.sip_meta.isValid()){
		           start_first_pass();
			}
			else
				tb_start_round.apply();
				
			//compression round: xor msg
		        //note: for finalization rounds msg is zero, no effect
		        //v3^=m
		        sip_1_odd();
		        //first SipRound
		        sip_1_a();
		        sip_1_b();
		        sip_2_a();
		        sip_3_a();
		        sip_3_b();
		        sip_4_a();
		        sip_4_b_odd();
		        //second SipRound
		        sip_1_a();
		        sip_1_b();
		        sip_2_a();
		        sip_3_a();
		        sip_3_b();
		        tb_pre_end.apply();
		        sip_4_a();
		        //v0^=m
		        sip_4_b_even();

		        // randomly choose a recirculation port
		        get_rnd_bit();
		        if (ig_md.rnd_bit == 0){
			    ig_md.rnd_port_for_recirc = 68;
		        } else{
			    ig_md.rnd_port_for_recirc = 68 + 128;
		        }
                        
		        tb_recirc_decision.apply();
		        if (!hdr.sip_meta.isValid()){ // should be ending at this step, and result is in the first 4 bytes of sip
		            hdr.whattodo.case_num = 3;
		        }
		    }
		
		else if (hdr.whattodo.case_num == 3){
		
		    if (hdr.hash_stage.stage_num == 1){
		        
		        bit<REVF_LENGTH> cur_revf;
                        bit<SVF_LENGTH> new_svf;
                
                        if (ig_md.trans_id == 0) {
                            cur_revf = hdr.revfs[0].revf;
                        }
                        else if (ig_md.trans_id == 1) {
                            cur_revf = hdr.revfs[1].revf;
                        }
                        else if (ig_md.trans_id == 2) {
                            cur_revf = hdr.revfs[2].revf;
                        }
                        else if (ig_md.trans_id == 3) {
                            cur_revf = hdr.revfs[3].revf;
                        }
                        else if (ig_md.trans_id == 4) {
                            cur_revf = hdr.revfs[1].revf;
                        }
                        else if (ig_md.trans_id == 5) {
                            cur_revf = hdr.revfs[2].revf;
                        }
                        else if (ig_md.trans_id == 6) {
                            cur_revf = hdr.revfs[3].revf;
                        }
                        else if (ig_md.trans_id == 7) {
                            cur_revf = hdr.revfs[1].revf;
                        }
                        else {
                            cur_revf = 0;
                        }
                        
                        if (cur_revf != hdr.sip.m_0)
                            drop();
                   
                        else {
							/*
                            bit<96> padding = 0;
							bit<128> temp = hdr.validation.svf++padding; 
					
							// turn these into automated so that changing hash input length doesn't change these assignments
							hdr.sip.m_0 = temp[127:96];
							hdr.sip.m_1 = temp[95:64];
							hdr.sip.m_2 = temp[63:32];
							hdr.sip.m_3 = temp[31:0];
							*/

							hdr.sip.m_0 = hdr.validation.svf;
		            
                            hdr.hash_stage.stage_num = 2;
                            hdr.whattodo.case_num = 2;
                        }
                        
		    }
		    
		    else if (hdr.hash_stage.stage_num == 2){
		        hdr.validation.svf = hdr.sip.m_0;
		        
		        hdr.path.push_front(1);
                hdr.path[0].setValid();
                hdr.path[0].transition_id = ig_md.trans_id;
                hdr.pathmeta.path_length = hdr.pathmeta.path_length+1;
                hdr.ipv4.total_len = hdr.ipv4.total_len+1;
		        
		        hdr.udp.dst_port = SIP_PORT;
		        hdr.whattodo.setInvalid();
		        hdr.hash_stage.setInvalid();
		        hdr.sip.setInvalid(); 
		        hdr.sip_meta.setInvalid();   
		    } 
		}
		
		
        }
}

control SwitchEgress(
		inout header_t hdr,
		inout eg_metadata_t eg_md,
		in egress_intrinsic_metadata_t eg_intr_md,
		in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
		inout egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr,
		inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {

	action drop(){
		eg_intr_md_for_dprsr.drop_ctl = 0x1; // Drop packet.
	}
	
	action nop() {
	}

	action final_round_xor(){
		hdr.udp.dst_port=SIP_PORT;
		#define eg_writeout_m(i) hdr.sip.m_##i = 0;
		__LOOP(NUM_WORDS,eg_writeout_m)
		@in_hash { hdr.sip.m_0 = hdr.sip_meta.v_1 ^ hdr.sip_meta.v_3; }
		hdr.sip_meta.setInvalid();
	}

	action sip_init(bit<32> key_0, bit<32> key_1){
		hdr.sip_meta.v_0 = key_0 ^ const_0;
		hdr.sip_meta.v_1 = key_1 ^ const_1;
		hdr.sip_meta.v_2 = key_0 ^ const_2;
		hdr.sip_meta.v_3 = key_1 ^ const_3;
	}

	#define MSG_VAR_EG eg_md.sip_tmp.i_0
	action sip_1_odd(){
		//for first SipRound in set of <c> SipRounds
		//i_3 = i_3 ^ message
		hdr.sip_meta.v_3 = hdr.sip_meta.v_3 ^ MSG_VAR_EG;
	}
	action sip_1_a(){
		//a_0 = i_0 + i_1
		eg_md.sip_tmp.a_0 = hdr.sip_meta.v_0 + hdr.sip_meta.v_1;
		//a_2 = i_2 + i_3
		eg_md.sip_tmp.a_2 = hdr.sip_meta.v_2 + hdr.sip_meta.v_3;
		//a_1 = i_1 << 5
		@in_hash { eg_md.sip_tmp.a_1 = hdr.sip_meta.v_1[26:0] ++ hdr.sip_meta.v_1[31:27]; }
	}
	action sip_1_b(){
		//a_3 = i_3 << 8
		eg_md.sip_tmp.a_3 = hdr.sip_meta.v_3[23:0] ++ hdr.sip_meta.v_3[31:24];

	}
	action sip_2_a(){
		//b_1 = a_1 ^ a_0
		eg_md.sip_tmp.i_1 = eg_md.sip_tmp.a_1 ^ eg_md.sip_tmp.a_0;
		//b_3 = a_3 ^ a_2
		eg_md.sip_tmp.i_3 = eg_md.sip_tmp.a_3 ^ eg_md.sip_tmp.a_2;
		// b_0 = a_0 << 16
		eg_md.sip_tmp.i_0 = eg_md.sip_tmp.a_0[15:0] ++ eg_md.sip_tmp.a_0[31:16];
		//b_2 = a_2
		eg_md.sip_tmp.i_2 = eg_md.sip_tmp.a_2;
	}

	action sip_3_a(){
		//c_2 = b_2 + b_1
		eg_md.sip_tmp.a_2 = eg_md.sip_tmp.i_2 + eg_md.sip_tmp.i_1;
		//c_0 = b_0 + b_3
		eg_md.sip_tmp.a_0 = eg_md.sip_tmp.i_0 + eg_md.sip_tmp.i_3;
		//c_1 = b_1 << 13
		@in_hash { eg_md.sip_tmp.a_1 = eg_md.sip_tmp.i_1[18:0] ++ eg_md.sip_tmp.i_1[31:19]; }
	}
	action sip_3_b(){
		//c_3 = b_3 << 7
		@in_hash { eg_md.sip_tmp.a_3 = eg_md.sip_tmp.i_3[24:0] ++ eg_md.sip_tmp.i_3[31:25]; }
	}

	action sip_4_a(){
		//d_1 = c_1 ^ c_2
		hdr.sip_meta.v_1 = eg_md.sip_tmp.a_1 ^ eg_md.sip_tmp.a_2;
		//d_3 = c_3 ^ c_0 i
		hdr.sip_meta.v_3 = eg_md.sip_tmp.a_3 ^ eg_md.sip_tmp.a_0;
		//d_2 = c_2 << 16
		hdr.sip_meta.v_2 = eg_md.sip_tmp.a_2[15:0] ++ eg_md.sip_tmp.a_2[31:16];

	}
	action sip_4_b_odd(){
		//d_0 = c_0
		hdr.sip_meta.v_0 = eg_md.sip_tmp.a_0;
	}
	action sip_4_b_even(){
		//d_0 = c_0 ^ message
		hdr.sip_meta.v_0 = eg_md.sip_tmp.a_0 ^ MSG_VAR_EG;
	}

	//compression rounds
	// round 0~(2*NUM_WORDS-1)
	#define eg_def_start_m(i) action start_m_## i ##_compression(){\
		eg_md.sip_tmp.round_type = ROUND_TYPE_COMPRESSION;		\
		MSG_VAR_EG = hdr.sip.m_## i;								\
	}
	__LOOP(NUM_WORDS,eg_def_start_m)

	//round 2*NUM_WORDS (first 2 finalization rounds)
	action start_finalization_a(){
		eg_md.sip_tmp.round_type = ROUND_TYPE_FINALIZATION;
		MSG_VAR_EG = 0;
		// also xor v2 with FF at beginning of first finalization pass
		hdr.sip_meta.v_2 = hdr.sip_meta.v_2 ^ 32w0xff;
	}
	//round 2*NUM_WORDS+2 (last 2 finalization rounds)
	action start_finalization_b(){
		eg_md.sip_tmp.round_type = ROUND_TYPE_END;
		MSG_VAR_EG = 0;
	}

	table tb_start_round {
		key = {
			hdr.sip_meta.curr_round: exact;
		}
		size = 32;
		actions = {
			#define eg_actname_start_m_mul2plus1(ix2p1) start_m_## ix2p1 ##_compression;
			#define eg_actname_start_m_mul2(ix2) __ADD(1,ix2,eg_actname_start_m_mul2plus1)
			#define eg_actname_start_m(i) __MUL(2,i, eg_actname_start_m_mul2)
			#if NUM_WORDS%2==0
				__LOOP(NUM_WORDS_EG, eg_actname_start_m)
				start_finalization_b;
			#else
				__LOOP(NUM_WORDS_EG, eg_actname_start_m)
				start_finalization_a;
			#endif
		}
		const entries = {
			#define eg_match_start_m_mul2plus1(ix2p1) (ix2p1*2): start_m_## ix2p1 ##_compression();
			#define eg_match_start_m_mul2(ix2) __ADD(1,ix2,eg_match_start_m_mul2plus1)
			#define eg_match_start_m(i) __MUL(2,i, eg_match_start_m_mul2)
			#if NUM_WORDS%2==0
				__LOOP(NUM_WORDS_EG, eg_match_start_m)
				(2*NUM_WORDS+2): start_finalization_b;
			#else
				__LOOP(NUM_WORDS_EG, eg_match_start_m)
				(2*NUM_WORDS): start_finalization_a;
			#endif
		}
	}

	#define eg_def_pre_end_m(i) action pre_end_m_## i ##_compression(){\
		MSG_VAR_EG = hdr.sip.m_## i;									\
	}
	__LOOP(NUM_WORDS,eg_def_pre_end_m)
	action pre_end_finalization_a(){
		MSG_VAR_EG = 0;
	}
	action pre_end_finalization_b(){
		MSG_VAR_EG = 0;
	}

	table tb_pre_end{
		key = {
			hdr.sip_meta.curr_round: exact;
		}
		size = 32;
		actions = {
			#define eg_actname_pre_end_m_mul2plus1(ix2p1) pre_end_m_## ix2p1 ##_compression;
			#define eg_actname_pre_end_m_mul2(ix2) __ADD(1,ix2,eg_actname_pre_end_m_mul2plus1)
			#define eg_actname_pre_end_m(i) __MUL(2,i, eg_actname_pre_end_m_mul2)
			#if NUM_WORDS%2==0
				__LOOP(NUM_WORDS_EG, eg_actname_pre_end_m)
				start_finalization_b;
			#else
				__LOOP(NUM_WORDS_EG, eg_actname_pre_end_m)
				start_finalization_a;
			#endif
		}
		const entries = {
			#define eg_match_pre_end_m_mul2plus1(ix2p1) (ix2p1*2): pre_end_m_## ix2p1 ##_compression();
			#define eg_match_pre_end_m_mul2(ix2) __ADD(1,ix2,eg_match_pre_end_m_mul2plus1)
			#define eg_match_pre_end_m(i) __MUL(2,i, eg_match_pre_end_m_mul2)
			#if NUM_WORDS%2==0
				__LOOP(NUM_WORDS_EG, eg_match_pre_end_m)
				(2*NUM_WORDS+2): start_finalization_b;
			#else
				__LOOP(NUM_WORDS_EG, eg_match_pre_end_m)
				(2*NUM_WORDS): start_finalization_a;
			#endif
		}
		}
		
		action start_first_pass(){
		//first pass init
	
		//hdr.sip.setValid();
		// set value of sip
		hdr.sip_meta.setValid();
		hdr.sip_meta.curr_round=0;

		sip_init(SIP_KEY_0, SIP_KEY_1);
		start_m_0_compression();

		//routing_decision();
	    }


	apply {
	
	         if (hdr.whattodo.case_num == 2){
		    
		        //logic check for first pass
			if(!hdr.sip_meta.isValid()){
		           start_first_pass();
			}
			else
				tb_start_round.apply();
				
			//compression round: xor msg
		        //note: for finalization rounds msg is zero, no effect//v3^=m
		        sip_1_odd();
		        //first SipRound
		        sip_1_a();
		        sip_1_b();
		        sip_2_a();
		        sip_3_a();
		        sip_3_b();
		        sip_4_a();
		        sip_4_b_odd();
		        //second SipRound
		        sip_1_a();
		        sip_1_b();
		        sip_2_a();
		        sip_3_a();
		        sip_3_b();
		        tb_pre_end.apply();
		        sip_4_a();
		        //v0^=m
		        sip_4_b_even();

		        if(hdr.sip_meta.curr_round < (NUM_WORDS*2+2)){
			    //need more rounds in ingress pipeline, packet should be during recirculation right now
			    hdr.sip_meta.curr_round = hdr.sip_meta.curr_round + 2;
		        }else{
			    final_round_xor();
		        }
		}
		
		else if (hdr.whattodo.case_num == 3){
		
		    if (hdr.hash_stage.stage_num == 1){
		        
		        bit<REVF_LENGTH> cur_revf;
                        bit<SVF_LENGTH> new_svf;
                
                        if (eg_md.trans_id == 0) {
                            cur_revf = hdr.revfs[0].revf;
                        }
                        else if (eg_md.trans_id == 1) {
                            cur_revf = hdr.revfs[1].revf;
                        }
                        else if (eg_md.trans_id == 2) {
                            cur_revf = hdr.revfs[2].revf;
                        }
                        else if (eg_md.trans_id == 3) {
                            cur_revf = hdr.revfs[3].revf;
                        }
                        else if (eg_md.trans_id == 4) {
                            cur_revf = hdr.revfs[1].revf;
                        }
                        else if (eg_md.trans_id == 5) {
                            cur_revf = hdr.revfs[2].revf;
                        }
                        else if (eg_md.trans_id == 6) {
                            cur_revf = hdr.revfs[3].revf;
                        }
                        else if (eg_md.trans_id == 7) {
                            cur_revf = hdr.revfs[1].revf;
                        }
                        else {
                            cur_revf = 0;
                        }
                        
                        if (cur_revf != hdr.sip.m_0)
                            drop();
                   
                        else {
                    // bit<96> padding = 0;
		            // bit<128> temp = hdr.validation.svf++padding; 
		    
		            // turn these into automated so that changing hash input length doesn't change these assignments
		            hdr.sip.m_0 = hdr.validation.svf;
		            hdr.sip.m_1 = 0;
		            hdr.sip.m_2 = 0;
		            hdr.sip.m_3 = 0;
		            
                            hdr.hash_stage.stage_num = 2;
                            hdr.whattodo.case_num = 2;
                        }
                        
		    }
		    
		    else if (hdr.hash_stage.stage_num == 2){
		        hdr.validation.svf = hdr.sip.m_0;
		        
		        hdr.path.push_front(1);
                        hdr.path[0].setValid();
                        hdr.path[0].transition_id = eg_md.trans_id;
                        hdr.pathmeta.path_length = hdr.pathmeta.path_length+1;
                        hdr.ipv4.total_len = hdr.ipv4.total_len+1;
		        
		        hdr.udp.dst_port = SIP_PORT;
		        hdr.whattodo.setInvalid();
		        hdr.hash_stage.setInvalid();
		        hdr.sip.setInvalid(); 
		        hdr.sip_meta.setInvalid();   
		    } 
		}
		
	
	}
}	

Pipeline(SwitchIngressParser(),
		SwitchIngress(),
		SwitchIngressDeparser(),
		SwitchEgressParser(),
		SwitchEgress(),
		SwitchEgressDeparser()
	) pipe;

Switch(pipe) main;
