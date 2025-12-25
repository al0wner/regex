################################################################################
 #  Copyright (C) 2024 Intel Corporation
 #
 #  Licensed under the Apache License, Version 2.0 (the "License");
 #  you may not use this file except in compliance with the License.
 #  You may obtain a copy of the License at
 #
 #  http://www.apache.org/licenses/LICENSE-2.0
 #
 #  Unless required by applicable law or agreed to in writing,
 #  software distributed under the License is distributed on an "AS IS" BASIS,
 #  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 #  See the License for the specific language governing permissions
 #  and limitations under the License.
 #
 #
 #  SPDX-License-Identifier: Apache-2.0
################################################################################


import logging
import random
import time

from ptf import config
import ptf.testutils as testutils
from p4testutils.misc_utils import *
from bfruntime_client_base_tests import BfRuntimeTest
import bfrt_grpc.client as gc
import ipaddress

##### Required for Thrift #####
import pd_base_tests

##### ******************* #####

logger = get_logger()
swports = get_sw_ports()


def validation_bytearr(dst_id=0, dfa_state=0, revf_length=1, datahash=0, svf=0, revf_data=0,path_length=0):
    ret = bytearray()
    ret += dst_id.to_bytes(1, byteorder='big')
    ret += dfa_state.to_bytes(1, byteorder='big')
    ret += revf_length.to_bytes(1, byteorder='big')
    ret += datahash.to_bytes(4, byteorder='big')
    ret += svf.to_bytes(4, byteorder='big')
    ret += revf_data.to_bytes(4, byteorder='big')
    ret += path_length.to_bytes(1, byteorder='big')
    return ret

def sip_bytearr(sip_0=0, sip_1=0, sip_2=0, sip_3=0, sip_4=0):
    ret = bytearray()
    ret += sip_0.to_bytes(4, byteorder='big')
    ret += sip_1.to_bytes(4, byteorder='big')
    ret += sip_2.to_bytes(4, byteorder='big')
    ret += sip_3.to_bytes(4, byteorder='big')
    ret += sip_4.to_bytes(4, byteorder='big')
    return ret




# Thie generates a simple IP packet and then attaches the validation header.
def validation_packet(dst_id=0, dfa_state=0, revf_length=1, datahash=0, svf=0, revf_data=0, path_length=0):
    inner_bytearr = validation_bytearr(dst_id, dfa_state, revf_length, datahash, svf, revf_data, path_length)
    pkt = testutils.simple_ipv4ip_packet(eth_dst='00:11:22:33:44:55', eth_src='11:33:55:77:99:00', ip_dst = '10.0.2.2', inner_frame = bytes(inner_bytearr))
    pkt["IP"].proto = 0xf0
    return pkt

def hashed_packet(dst_id=0, dfa_state=0, revf_length=1, datahash=0, svf=0, revf_data=0, path_length=0, sip_0=0, sip_1=0, sip_2=0, sip_3=0, sip_4=0):
    val_arr = validation_bytearr(dst_id, dfa_state, revf_length, datahash, svf, revf_data, path_length)
    sip_arr = sip_bytearr(sip_0, sip_1, sip_2, sip_3, sip_4)
    inner_bytearr =  sip_arr + val_arr
    print(f"inner_len : {len(inner_bytearr)}")
    pkt = testutils.simple_ipv4ip_packet(eth_dst='00:11:22:33:44:55', eth_src='11:33:55:77:99:00', ip_dst = '10.0.2.2', inner_frame = bytes(inner_bytearr))
    pkt["IP"].proto = 0xf2
    return pkt

# Configure forwarding rules
def _forward_table_add(table, target, dstip, prefix_len, dstmac, port):
    table.entry_add(
        target,
        [table.make_key(
            [gc.KeyTuple('hdr.ipv4.dst_addr', dstip, None, prefix_len)])],
        [table.make_data(
            [gc.DataTuple('dst_addr', dstmac),
             gc.DataTuple('port', port)
             #gc.DataTuple('$COUNTER_SPEC_BYTES', c_pkts),
             #gc.DataTuple('$COUNTER_SPEC_PKTS', c_bytes)
             ],
            'SwitchIngress.ipv4_forward')])
# Configure the DFA transition rule.
# Based on the current dfa id (corresponds to each invariant) and dfa state, set the next state and the transition id.
def _dfa_table_add(table, target, dfa_id, dfa_state, next_state, trans_id):
    table.entry_add(
        target,
        [table.make_key(
            [gc.KeyTuple('hdr.validation.dfa_id', dfa_id),
             gc.KeyTuple('hdr.validation.dfa_state', dfa_state)])],
        [table.make_data(
            [gc.DataTuple('state', next_state),
             gc.DataTuple('transition_id', trans_id)
             #gc.DataTuple('$COUNTER_SPEC_BYTES', c_pkts),
             #gc.DataTuple('$COUNTER_SPEC_PKTS', c_bytes)
             ],
            'SwitchIngress.dfa_transition')])

# Configure the forwarding port for hashing.
def _tohash_table_add(table, target, eg_port):
    table.default_entry_set(
    target,
    table.make_data([gc.DataTuple('eg_port', eg_port)], 'SwitchIngress.send_to_hash')
)

# When the ingress packet must be hashed
class ToHashTest(BfRuntimeTest):
    def setUp(self):
        client_id = 0
        p4_name = "dfa"
        BfRuntimeTest.setUp(self, client_id, p4_name)

    def runTest(self):
        ig_port = swports[1]
        eg_port = swports[2]

        print(f"ig_port, eg_port = {ig_port}, {eg_port}")

        smac = '11:33:55:77:99:00'
        dstip = '10.0.2.0'
        prefix_len = 24
        dstmac = '00:11:22:33:44:55'

        # Configure the DFA transitions.
        dfa_id = 0
        dfa_state = 0
        next_state = 1
        trans_id = 0

        # Halfsiphash is connected through the following port
        hash_egport = 13

        bfrt_info = self.interface.bfrt_info_get("dfa")
        forward_table = bfrt_info.table_get("SwitchIngress.ipv4_lpm")
        forward_table.info.key_field_annotation_add("hdr.ipv4.dst_addr", "ipv4")
        forward_table.info.data_field_annotation_add("dst_addr", "SwitchIngress.ipv4_forward", "mac")
        dfa_table = bfrt_info.table_get("SwitchIngress.dfa_trans")
        tohash_table = bfrt_info.table_get("SwitchIngress.to_hash")

        pkt = validation_packet(revf_data=0xaba88f14)
        print(type(pkt))
        #exp_pkt = pkt

        target = gc.Target(device_id=0, pipe_id=0xffff)

        _forward_table_add(forward_table, target, dstip, prefix_len, dstmac, eg_port)
        _dfa_table_add(dfa_table, target, dfa_id, dfa_state, next_state, trans_id)
        _tohash_table_add(tohash_table, target, hash_egport)
        
        testutils.send_packet(self, ig_port, pkt)
        print("Sent packet:")
        pkt.show2()

'''
# When the ingress packet must be forwarded (revf matches hashed value)
class ForwardTest(BfRuntimeTest):
    def setUp(self):
        client_id = 0
        p4_name = "dfa"
        BfRuntimeTest.setUp(self, client_id, p4_name)

    def runTest(self):
        ig_port = swports[1]
        eg_port = swports[2]
        smac = '11:33:55:77:99:00'
        dstip = '10.0.2.0'
        prefix_len = 24
        dstmac = '00:11:22:33:44:55'

        # Configure the DFA transitions.
        dfa_id = 0
        dfa_state = 0
        next_state = 1
        trans_id = 0

        # Halfsiphash is connected through the following port
        hash_egport = 13

        bfrt_info = self.interface.bfrt_info_get("dfa")
        forward_table = bfrt_info.table_get("SwitchIngress.ipv4_lpm")
        forward_table.info.key_field_annotation_add("hdr.ipv4.dst_addr", "ipv4")
        forward_table.info.data_field_annotation_add("dst_addr", "SwitchIngress.ipv4_forward", "mac")
        dfa_table = bfrt_info.table_get("SwitchIngress.dfa_trans")
        tohash_table = bfrt_info.table_get("SwitchIngress.to_hash")

        pkt = hashed_packet()
        print(type(pkt))
        # exp_pkt = pkt

        target = gc.Target(device_id=0, pipe_id=0xffff)

        testutils.send_packet(self, ig_port, pkt)
        print("Sent packet:")
        pkt.show2()

# When the ingress packet must be dropped (revf does not match hashed value)
class DropTest(BfRuntimeTest):
    def setUp(self):
        client_id = 0
        p4_name = "dfa"
        BfRuntimeTest.setUp(self, client_id, p4_name)

    def runTest(self):
        ig_port = swports[1]
        eg_port = swports[2]
        smac = '11:33:55:77:99:00'
        dstip = '10.0.2.0'
        prefix_len = 24
        dstmac = '00:11:22:33:44:55'

        # Configure the DFA transitions.
        dfa_id = 0
        dfa_state = 0
        next_state = 1
        trans_id = 0

        # Halfsiphash is connected through the following port
        hash_egport = 13

        bfrt_info = self.interface.bfrt_info_get("dfa")
        forward_table = bfrt_info.table_get("SwitchIngress.ipv4_lpm")
        forward_table.info.key_field_annotation_add("hdr.ipv4.dst_addr", "ipv4")
        forward_table.info.data_field_annotation_add("dst_addr", "SwitchIngress.ipv4_forward", "mac")
        dfa_table = bfrt_info.table_get("SwitchIngress.dfa_trans")
        tohash_table = bfrt_info.table_get("SwitchIngress.to_hash")

        pkt = hashed_packet(sip_0=0x23232323, sip_1=0x45454545)
        print(type(pkt))
        # exp_pkt = pkt

        target = gc.Target(device_id=0, pipe_id=0xffff)

        testutils.send_packet(self, ig_port, pkt)
        print("Sent packet:")
        pkt.show2()
'''

