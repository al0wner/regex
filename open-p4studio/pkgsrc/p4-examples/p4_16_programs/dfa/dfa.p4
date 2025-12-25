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
#define KEY_LENGTH 32

#define DFA_COUNT_BITS 8  // How many different DFAs can we define?
#define DFA_STATE_BITS 8  // How many bits do we need to represent the current state?
#define TRANS_ID_BITS 16 // How many bits do we need to represent each transition within a DFA?
#define BITVEC_SIZE 64
#define TIMESTAMP_LENGTH 48


#define TYPE_IPV4 0x800
#define VALIDATION_PROTO 0xF0
#define SIP_PROTO 0xF1
#define SIP_2_PROTO 0xF2

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



header validation_h {
    bit<48> timestamp;   // to prevent replay attack
    bit<SVF_LENGTH> svf; // sequential hash
    bit<DFA_COUNT_BITS> dfa_id;		 // used when there are multiple instances of DFAs for different ECs
    bit<DFA_STATE_BITS> dfa_state;
    
    //The total size of the following fields is dependent on the size of DFA_STATE_BITS (2^DFA_STATE_BITS total)
    bit<BITVEC_SIZE> bitvec_1;
    bit<BITVEC_SIZE> bitvec_2;
    bit<BITVEC_SIZE> bitvec_3;
    bit<BITVEC_SIZE> bitvec_4;
	/////////////////////////////////////////////////////
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

header sip_h {
	// hash_i = MAC_{k_i} (timestamp || DFA_id || transition_id || hash_i )
	bit<SVF_LENGTH> svf;
	bit<DFA_COUNT_BITS> dfa_id;
	bit<TRANS_ID_BITS> trans_id;
	bit<48> timestamp;
	bit<16> orig_eg_port;
}

struct ig_metadata_t {
	bit<TRANS_ID_BITS> trans_id;
}

struct eg_metadata_t {
}


struct header_t {
// apparently order of headers doesn't matter if they are read correctly...
	ethernet_h ethernet;
	ipv4_h ipv4;
	sip_h sip;
	validation_h validation;
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
		pkt.emit(hdr.sip);
		pkt.emit(hdr.validation);
	}
}


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
		pkt.emit(hdr.sip);
		pkt.emit(hdr.validation);
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

	action ipv4_forward(bit<48> dst_addr, bit<9> port) {
        ig_intr_tm_md.ucast_egress_port = port;
		hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        hdr.ethernet.src_addr = hdr.ethernet.dst_addr;
        hdr.ethernet.dst_addr = dst_addr;
		ig_intr_dprsr_md.drop_ctl = 0x0;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dst_addr: lpm;
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


	action mark_bitvec_1(bit<BITVEC_SIZE> statebit) {
		hdr.validation.bitvec_1 = hdr.validation.bitvec_1 | statebit;
	}
	action mark_bitvec_2(bit<BITVEC_SIZE> statebit) {
		hdr.validation.bitvec_2 = hdr.validation.bitvec_2 | statebit;
	}
	action mark_bitvec_3(bit<BITVEC_SIZE> statebit) {
		hdr.validation.bitvec_3 = hdr.validation.bitvec_3 | statebit;
	}
	action mark_bitvec_4(bit<BITVEC_SIZE> statebit) {
		hdr.validation.bitvec_4 = hdr.validation.bitvec_4 | statebit;
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

	table bitvec1 {
		key = {
			hdr.validation.dfa_id: exact;
			ig_md.trans_id: exact;
		}

		actions = {
			mark_bitvec_1;
			NoAction;
		}
		size = 512;
		default_action = NoAction();
	}

	table bitvec2 {
		key = {
			hdr.validation.dfa_id: exact;
			ig_md.trans_id: exact;
		}

		actions = {
			mark_bitvec_2;
			NoAction;
		}
		size = 512;
		default_action = NoAction();
	}

	table bitvec3 {
		key = {
			hdr.validation.dfa_id: exact;
			ig_md.trans_id: exact;
		}

		actions = {
			mark_bitvec_3;
			NoAction;
		}
		size = 512;
		default_action = NoAction();
	}

	table bitvec4 {
		key = {
			hdr.validation.dfa_id: exact;
			ig_md.trans_id: exact;
		}

		actions = {
			mark_bitvec_4;
			NoAction;
		}
		size = 512;
		default_action = NoAction();
	}

	action send_to_hash(bit<9> eg_port) {
		hdr.sip.setValid();
		hdr.sip.svf = hdr.validation.svf;
		hdr.sip.dfa_id = hdr.validation.dfa_id;
		hdr.sip.trans_id = ig_md.trans_id;
		hdr.sip.timestamp = hdr.validation.timestamp;
		hdr.sip.orig_eg_port = (bit<16>)ig_intr_tm_md.ucast_egress_port;
		ig_intr_tm_md.ucast_egress_port = eg_port;
	}

	table to_hash {
		key = {}
		actions = {
			send_to_hash;
		}
		size = 1;
		default_action = send_to_hash(13);
	}


	apply {
		dfa_trans.apply();

		bitvec1.apply();
		bitvec2.apply();
		bitvec3.apply();
		bitvec4.apply();

		ipv4_lpm.apply();

		if(ig_intr_dprsr_md.drop_ctl == 0)
			to_hash.apply();
		
		//ig_intr_tm_md.bypass_egress = 1w1; // bypass egress
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
