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
    
def need_hash_packet(dst_id=0, dfa_state=1, revf_length=1, datahash=0, svf=0, revf_data=0, path_length=0, sip_0=1, sip_1=2, sip_2=3, sip_3=4, sip_4=5):
    val_arr = validation_bytearr(dst_id, dfa_state, revf_length, datahash, svf, revf_data, path_length)
    sip_arr = sip_bytearr(sip_0, sip_1, sip_2, sip_3, sip_4)
    inner_bytearr =  sip_arr + val_arr
    print(f"inner_len : {len(inner_bytearr)}")
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

# Hash test
class HashTest(BfRuntimeTest):
    def setUp(self):
        client_id = 0
        p4_name = "halfsiphash"
        BfRuntimeTest.setUp(self, client_id, p4_name)

    def runTest(self):
        ig_port=3
        
        pkt = need_hash_packet()
        print(type(pkt))
        # exp_pkt = pkt

        target = gc.Target(device_id=0, pipe_id=0xffff)

        testutils.send_packet(self, ig_port, pkt)
        print("Sent packet:")
        pkt.show2()


