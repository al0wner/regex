/*******************************************************************************
 *  Copyright (C) 2024 Intel Corporation
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions
 *  and limitations under the License.
 *
 *
 *  SPDX-License-Identifier: Apache-2.0
 ******************************************************************************/


#include <iostream>
#include <pdfixed_thrift/bfn_pd_rpc_server.h>
#include <thrift/protocol/TBinaryProtocol.h>
#include <thrift/server/TSimpleServer.h>
#include <thrift/server/TThreadedServer.h>
#include <thrift/transport/TServerSocket.h>
#include <thrift/transport/TBufferTransports.h>
#include <thrift/processor/TMultiplexedProcessor.h>

using namespace ::apache::thrift;
using namespace ::apache::thrift::protocol;
using namespace ::apache::thrift::transport;
using namespace ::apache::thrift::server;

using ::std::shared_ptr;

#include <pthread.h>

// All the supported Thrift service handlers :
#include "conn_mgr_pd_rpc_server.ipp"
#include "mc_pd_rpc_server.ipp"
#include "mirror_pd_rpc_server.ipp"
#include "sd_pd_rpc_server.ipp"
#include "devport_mgr_pd_rpc_server.ipp"
#include "port_mgr_pd_rpc_server.ipp"
#include "pkt_pd_rpc_server.ipp"
#include "tm_api_rpc_server.ipp"
#include "pal_rpc_server.ipp"
#include "plcmt_pd_rpc_server.ipp"
#include "knet_mgr_pd_rpc_server.ipp"
#include "pipemgr_api_rpc_server.ipp"
#include "ts_pd_rpc_server.ipp"

static pthread_mutex_t cookie_mutex;
static pthread_cond_t cookie_cv;
static void *cookie;

/*
 * Thread wrapper for starting the server
 */
 
 struct rpc_thread_args {
    bool is_local_only;
    uint16_t pd_api_port;
};

static void *rpc_server_thread(void *arg) {

  struct rpc_thread_args *args = (struct rpc_thread_args *)arg;
  bool is_local_only = args->is_local_only;
  uint16_t pd_api_port = args->pd_api_port;
  free(args);  
  int port = pd_api_port;

  std::shared_ptr<mcHandler> mc_handler(new mcHandler());
  std::shared_ptr<mirrorHandler> mirror_handler(new mirrorHandler());
  std::shared_ptr<sdHandler> sd_handler(new sdHandler());
  std::shared_ptr<tmHandler> tm_handler(new tmHandler());
  std::shared_ptr<conn_mgrHandler> conn_mgr_handler(new conn_mgrHandler());
  std::shared_ptr<devport_mgrHandler> devport_mgr_handler(
      new devport_mgrHandler());
  std::shared_ptr<port_mgrHandler> port_mgr_handler(new port_mgrHandler());
  std::shared_ptr<palHandler> pal_handler(new palHandler());
  std::shared_ptr<pktHandler> pkt_handler(new pktHandler());
  std::shared_ptr<plcmtHandler> plcmt_handler(new plcmtHandler());
  std::shared_ptr<knet_mgrHandler> knet_mgr_handler(new knet_mgrHandler());
  std::shared_ptr<pipemgr_apiHandler> pipemgr_api_handler(
      new pipemgr_apiHandler());
  std::shared_ptr<tsHandler> ts_handler(new tsHandler());

  std::shared_ptr<TMultiplexedProcessor> processor(new TMultiplexedProcessor());
  processor->registerProcessor(
      "mc", std::shared_ptr<TProcessor>(new mcProcessor(mc_handler)));
  processor->registerProcessor(
      "mirror",
      std::shared_ptr<TProcessor>(new mirrorProcessor(mirror_handler)));
  processor->registerProcessor(
      "sd", std::shared_ptr<TProcessor>(new sdProcessor(sd_handler)));
  processor->registerProcessor(
      "tm", std::shared_ptr<TProcessor>(new tmProcessor(tm_handler)));
  processor->registerProcessor(
      "conn_mgr",
      std::shared_ptr<TProcessor>(new conn_mgrProcessor(conn_mgr_handler)));
  processor->registerProcessor(
      "devport_mgr",
      std::shared_ptr<TProcessor>(
          new devport_mgrProcessor(devport_mgr_handler)));
  processor->registerProcessor(
      "port_mgr",
      std::shared_ptr<TProcessor>(new port_mgrProcessor(port_mgr_handler)));
  processor->registerProcessor(
      "pal", std::shared_ptr<TProcessor>(new palProcessor(pal_handler)));
  processor->registerProcessor(
      "pkt", std::shared_ptr<TProcessor>(new pktProcessor(pkt_handler)));
  processor->registerProcessor(
      "plcmt", std::shared_ptr<TProcessor>(new plcmtProcessor(plcmt_handler)));
  processor->registerProcessor(
      "knet_mgr",
      std::shared_ptr<TProcessor>(new knet_mgrProcessor(knet_mgr_handler)));
  processor->registerProcessor(
      "pipemgr_api",
      std::shared_ptr<TProcessor>(
          new pipemgr_apiProcessor(pipemgr_api_handler)));
  processor->registerProcessor(
      "ts", std::shared_ptr<TProcessor>(new tsProcessor(ts_handler)));

  std::shared_ptr<TServerTransport> serverTransport(
      new TServerSocket(is_local_only ? "localhost" : "", port));
  std::shared_ptr<TTransportFactory> transportFactory(
      new TBufferedTransportFactory());
  std::shared_ptr<TProtocolFactory> protocolFactory(
      new TBinaryProtocolFactory());

  TThreadedServer server(
      processor, serverTransport, transportFactory, protocolFactory);

  pthread_mutex_lock(&cookie_mutex);
  cookie = (void *)processor.get();
  pthread_cond_signal(&cookie_cv);
  pthread_mutex_unlock(&cookie_mutex);

  server.serve();

  return NULL;
}

static pthread_t rpc_thread;

int start_bfn_pd_rpc_server(void **server_cookie, bool is_local_only, uint16_t pd_api_port) {
  pthread_mutex_init(&cookie_mutex, NULL);
  pthread_cond_init(&cookie_cv, NULL);

  std::cerr << "Starting PD-API RPC server on port " << pd_api_port
            << std::endl;

  *server_cookie = NULL;
  
  struct rpc_thread_args *args = (struct rpc_thread_args *)malloc(sizeof(*args));
  args->is_local_only = is_local_only;
  args->pd_api_port = pd_api_port;

int status = pthread_create(&rpc_thread, NULL, rpc_server_thread, args);

  if (status) return status;
  pthread_setname_np(rpc_thread, "bf_pd_rpc_srv");

  pthread_mutex_lock(&cookie_mutex);
  while (!cookie) {
    pthread_cond_wait(&cookie_cv, &cookie_mutex);
  }
  pthread_mutex_unlock(&cookie_mutex);

  *server_cookie = cookie;

  pthread_mutex_destroy(&cookie_mutex);
  pthread_cond_destroy(&cookie_cv);

  return 0;
}
