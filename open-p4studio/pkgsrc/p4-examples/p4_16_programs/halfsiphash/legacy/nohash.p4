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
/*
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
*/

// validation stuff
#define SVF_LENGTH 32
#define REVF_LENGTH 32
#define KEY_LENGTH 32
#define TRANS_ID_BITS 16
#define DFA_STATE_BITS 8
#define DATAHASH_LENGTH 32
#define TRANS_LENGTH 32
#define MAX_REVF_LENGTH 8  // need to cut parse bytes
#define MAX_PATH_LENGTH 8
#define TIMESTAMP_LENGTH 48
#define REVF_INPUT_LENGTH 120

#define TYPE_IPV4 0x800
#define VALIDATION_PROTO 0xF0

//const bit<16> TYPE_IPV4 = 0x800;
const bit<8> VALIDATION_PROTO = 0xF0;
const bit<8> SIP_PROTO = 0xF1;


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
	bit<SVF_LENGTH> svf;
	bit<DATAHASH_LENGTH> datahash;
	bit<TRANS_ID_BITS> trans_id;
	bit<48> timestamp;
}


struct header_t {
// apparently order of headers doesn't matter if they are read correctly...
	ethernet_h ethernet;
	ipv4_h ipv4;
	sip_inout_h sip;
	validation_h validation;
    revf_t[MAX_REVF_LENGTH] revfs;
    path_meta_t pathmeta;
    path_t[MAX_PATH_LENGTH] path;

	//tcp_h tcp;
	//udp_h udp;    
}
/*
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
*/
struct ig_metadata_t {
    /*
	bool recirc;
	bit<9> rnd_port_for_recirc;
	bit<1> rnd_bit;
	bit<5> pad;
	sip_tmp_h sip_tmp;
    */
	bit<KEY_LENGTH> key;
    bit<REVF_LENGTH> revf_prime;
    bit<TRANS_ID_BITS> trans_id;
    bit<8> revf_remaining;
    bit<8> path_remaining;
}


struct eg_metadata_t {
	//sip_tmp_h sip_tmp;
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
/*
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
*/
parser SwitchIngressParser(
		packet_in pkt,
		out header_t hdr,
		out ig_metadata_t ig_md,
		out ingress_intrinsic_metadata_t ig_intr_md) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        
        transition select(hdr.ipv4.protocol) {
            VALIDATION_PROTO: parse_validation;
            default: accept;
            
        }
    }
    
    state parse_validation {
        pkt.extract(hdr.validation);
        transition select(hdr.validation.revf_length) {
            0: parse_path_meta;
            default: parse_revfs_1;
        }
    }
    
    state parse_revfs_1 {
        pkt.extract(hdr.revfs.next);
        transition select(hdr.validation.revf_length) {
            1: parse_path_meta;
            default: parse_revfs_2;
        }
    }
    state parse_revfs_2 {
        pkt.extract(hdr.revfs.next);
        transition select(hdr.validation.revf_length) {
            2: parse_path_meta;
            default: parse_revfs_3;
        }
    }
    state parse_revfs_3 {
        pkt.extract(hdr.revfs.next);
        transition accept;
    }

    
    state parse_path_meta {
        pkt.extract(hdr.pathmeta);
        transition select(hdr.pathmeta.path_length) {
            0: accept;
            default: parse_path_1;
        }
    }
    
    state parse_path_1 {
        pkt.extract(hdr.path.next);
        transition select(hdr.pathmeta.path_length) {
            1: accept;
            default: parse_path_2;
        }
    }
    state parse_path_2 {
        pkt.extract(hdr.path.next);
        transition select(hdr.pathmeta.path_length) {
            2: accept;
            default: parse_path_3;
        }
    }

    state parse_path_3 {
        pkt.extract(hdr.path.next);
        transition accept;
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
		pkt.emit(hdr.validation);
		pkt.emit(hdr.revfs);
        pkt.emit(hdr.pathmeta);
        pkt.emit(hdr.path);
        //pkt.emit(hdr.whattodo);
        //pkt.emit(hdr.hash_stage);
		//pkt.emit(hdr.sip);
		//pkt.emit(hdr.sip_meta);
        //pkt.emit(hdr.tcp);
		//pkt.emit(hdr.udp);
	}
}

/*
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
*/

parser SwitchEgressParser(
		packet_in pkt,
		out header_t hdr,
		out eg_metadata_t eg_md,
		out egress_intrinsic_metadata_t eg_intr_md) {
	state start {
		transition accept;
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
		
		pkt.emit(hdr.validation);
		pkt.emit(hdr.revfs);
        pkt.emit(hdr.pathmeta);
        pkt.emit(hdr.path);
        /*
        pkt.emit(hdr.whattodo);
        pkt.emit(hdr.hash_stage);
		pkt.emit(hdr.sip);
		pkt.emit(hdr.sip_meta);
        pkt.emit(hdr.tcp);
		pkt.emit(hdr.udp);
		*/
		
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

	action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }


	
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
	apply {
		if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
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


	apply {
  
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
