/*
 * Copyright (C) 2011-2018 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <signal.h>

# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"

#include "Utility.h"
#include "Dump.h"
#include "Client.h"

#include "sgxsd.h"
#include "sabd.h"

#define MODE "traced_batch"

#include <iostream>
using namespace std;

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;
extern bucket_t bucket;
int actionCounter;

int initilize_ra() {

  // for the fucking remote attestation!
  // https://github.com/intel/sgx-ra-sample

  // other peoples with my problems:
  // https://software.intel.com/en-us/forums/intel-software-guard-extensions-intel-sgx/topic/814779

  bootSecureCommunication(global_eid);

  return 0;
}

/* Initialize the enclave:
 *   Step 1: try to retrieve the launch token saved by last transaction
 *   Step 2: call sgx_create_enclave to initialize an enclave instance
 *   Step 3: save the launch token if it is updated
 */
int initialize_enclave(void)
{
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;

  /* Call sgx_create_enclave to initialize an enclave instance */
  /* Debug Support: set 2nd parameter to 1 */
  ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
  if (ret != SGX_SUCCESS) {
      print_error_message(ret);
      return -1;
  }

  return 0;
}

/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate
     * the input string to prevent buffer overflow.
     */
    printf("%s", str);
}

/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);

    // 0 -> single entries fashion
    if(initialize_client(0) < 0) {
      cout << "Enter a character before exit ..." << endl;
      getchar();
      return -1;
    }

    /* Initialize the enclave */
    if(initialize_enclave() < 0){
        printf("Enter a character before exit ...\n");
        getchar();
        return -1;
    }

    if(initilize_ra() < 0) {
      cout << "Enter a character before exit ..." << endl;
      getchar();
      return -1;
    }

    setActionCounter(global_eid, &actionCounter);
    setBucket(global_eid, &bucket);

    sgx_status_t res;

    // res = hello(global_eid);
    // print_error_message(res);

    sgx_status_t ret;
    // printf("[INFO] Start warmup!\n");
    //
    // // // WARMUP
    // // for (int i = 0; i < MAX_WARM_UP; i++)
    // // {
    // //   sgxsd_node_init_args_t init_arg;
    // //   init_arg.pending_requests_table_order = 12;
    // //   sgxsd_enclave_node_init(global_eid, &ret, &init_arg);
    // //   sgxsd_enclave_set_current_quote(global_eid, &ret);
    // //   sgxsd_request_negotiation_request_t p_request;
    // //   sgxsd_request_negotiation_response_t p_response;
    // //   sgxsd_enclave_negotiate_request(global_eid, &ret, &p_request, &p_response);
    // //   sgxsd_server_init_args_t p_args;
    // //   p_args.max_ab_jids = 10;
    // //   sgxsd_server_state_handle_t state_handle = 0;
    // //   sgxsd_enclave_server_start(global_eid, &ret, &p_args, state_handle);
    // //   sgxsd_server_handle_call_args_t p_args2;
    // //   sgxsd_msg_header_t msg_header;
    // //   #define MSG_SIZE 10
    // //   uint8_t msg_data[MSG_SIZE];
    // //   size_t msg_size = MSG_SIZE;
    // //   sgxsd_msg_tag_t msg_tag;
    // //   sgxsd_server_state_handle_t state_handle2 = 0; // same of the previous one
    // //   // ret = sgxsd_enclave_server_call(global_eid, &ret, &p_args2, &msg_header, msg_data, msg_size, msg_tag, state_handle2);
    // //   sgxsd_enclave_server_call(global_eid, &ret, &p_args2, &msg_header, msg_data, msg_size, msg_tag, state_handle2);
    // //   sgxsd_server_terminate_args_t p_args3;
    // //   sgxsd_server_state_handle_t state_handle3 = 0; // same of the previous one
    // //   sgxsd_enclave_server_stop(global_eid, &ret, &p_args3, state_handle3);
    // // }
    // //
    // // printf("[INFO] End warmup!\n");
    //
    // for (int i = 0; i < MAX_TEST; i++)
    // {
      sgxsd_node_init_args_t init_arg;
      init_arg.pending_requests_table_order = 12;
      res = sgxsd_enclave_node_init(global_eid, &ret, &init_arg);
      // RUN_AND_DUMP(MODE, "sgxsd_enclave_node_init", sgxsd_enclave_node_init(global_eid, &ret, &init_arg))
      // dumpLen(MODE, "sgxsd_enclave_node_init", &actionCounter);
      // print_error_message(res);
      // print_error_message(ret);

      // sgx_status_t sgxsd_enclave_get_next_report(sgx_target_info_t qe_target_info, [out] sgx_report_t *p_report);
      // printf("Test: sgxsd_enclave_get_next_report()\n");
      // sgx_target_info_t qe_target_info;
      // sgx_report_t p_report;
      // res = sgxsd_enclave_get_next_report(global_eid, &ret, qe_target_info, &p_report);
      // print_error_message(res);
      // print_error_message(ret);

      res = sgxsd_enclave_set_current_quote(global_eid, &ret);
      // RUN_AND_DUMP(MODE, "sgxsd_enclave_set_current_quote", sgxsd_enclave_set_current_quote(global_eid, &ret))
      // dumpLen(MODE, "sgxsd_enclave_set_current_quote", &actionCounter);
      // // print_error_message(res);

      // printf("Test: sgxsd_enclave_negotiate_request()\n");
      // sgxsd_request_negotiation_request_t p_request;
      // sgxsd_request_negotiation_response_t p_response;
      // res = sgxsd_enclave_negotiate_request(global_eid, &ret, &p_request, &p_response);
      // RUN_AND_DUMP(MODE, "sgxsd_enclave_negotiate_request", sgxsd_enclave_negotiate_request(global_eid, &ret, &p_request, &p_response))
      // dumpLen(MODE, "sgxsd_enclave_negotiate_request", &actionCounter);
      // print_error_message(res);
      // print_error_message(ret);

      sgxsd_server_init_args_t p_args;
      p_args.max_ab_jids = 10;
      sgxsd_server_state_handle_t state_handle = 0;
      // // // printf("Test: sgxsd_enclave_server_start()\n");
      res = sgxsd_enclave_server_start(global_eid, &ret, &p_args, state_handle);
      // RUN_AND_DUMP(MODE, "sgxsd_enclave_server_start", sgxsd_enclave_server_start(global_eid, &ret, &p_args, state_handle))
      // dumpLen(MODE, "sgxsd_enclave_server_start", &actionCounter);
      // // print_error_message(res);
      // // print_error_message(ret);

      sgxsd_server_handle_call_args_t p_args2;
      sgxsd_msg_header_t msg_header;
      #define MSG_SIZE 10
      uint8_t msg_data[MSG_SIZE];
      size_t msg_size = MSG_SIZE;
      sgxsd_msg_tag_t msg_tag;
      sgxsd_server_state_handle_t state_handle2 = 0; // same of the previous one
      ret = sgxsd_enclave_server_call(global_eid, &ret, &p_args2, &msg_header, msg_data, msg_size, msg_tag, state_handle2);
      // RUN_AND_DUMP(MODE, "sgxsd_enclave_server_call", sgxsd_enclave_server_call(global_eid, &ret, &p_args2, &msg_header, msg_data, msg_size, msg_tag, state_handle2))
      // dumpLen(MODE, "sgxsd_enclave_server_call", &actionCounter);
      // // print_error_message(res);
      // // print_error_message(ret);

      sgxsd_server_terminate_args_t p_args3;
      sgxsd_server_state_handle_t state_handle3 = 0; // same of the previous one
      ret = sgxsd_enclave_server_stop(global_eid, &ret, &p_args3, state_handle3);
      // RUN_AND_DUMP(MODE, "sgxsd_enclave_server_stop", sgxsd_enclave_server_stop(global_eid, &ret, &p_args3, state_handle3))
      // dumpLen(MODE, "sgxsd_enclave_server_stop", &actionCounter);
      // // print_error_message(res);
      // // print_error_message(ret);
    // }

    printf("Info: SampleEnclave successfully returned.\n");

    makeEndMsg(global_eid);

    printf("sgx_destroy_enclave()\n");
    sgx_destroy_enclave(global_eid);

    return 0;
}

sgx_status_t sgxsd_ocall_reply(const sgxsd_msg_header_t *p_reply_header,
                               const uint8_t *reply_data, size_t reply_data_size,
                               sgxsd_msg_tag_t msg_tag) {
    // JNIEnv *env = g_sgxsd_thread_jni_env;
    // sgxsd_jni_msg_tag_t jni_msg_tag = *(sgxsd_jni_msg_tag_t *) msg_tag.p_tag;
    // free(msg_tag.p_tag);
    //
    // jsize j_reply_size = (jsize) reply_data_size;
    // jbyteArray j_reply_data = sgxsd_jni_to_byte_array(env, reply_data, j_reply_size);
    // jbyteArray j_reply_iv = sgxsd_jni_to_byte_array(env, p_reply_header->iv.data, sizeof(p_reply_header->iv.data));
    // jbyteArray j_reply_mac = sgxsd_jni_to_byte_array(env, p_reply_header->mac.data, sizeof(p_reply_header->mac.data));
    //
    // jobject j_callback_obj = (*env)->NewLocalRef(env, jni_msg_tag.j_callback_ref);
    // (*env)->DeleteGlobalRef(env, jni_msg_tag.j_callback_ref);
    // if (j_callback_obj != NULL) {
    //     // do the null/error checking and throwing an exception in the java callback
    //     (*env)->CallVoidMethod(env, j_callback_obj, jni_msg_tag.j_callback_method_id,
    //                            j_reply_data, j_reply_iv, j_reply_mac);
    //     (*env)->DeleteLocalRef(env, j_callback_obj);
    // }
    return SGX_SUCCESS;
}
