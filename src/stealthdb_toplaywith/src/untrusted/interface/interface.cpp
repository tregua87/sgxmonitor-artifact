#define MAX_PATH FILENAME_MAX

#include "untrusted/interface/interface.h"
#include "untrusted/interface/stdafx.h"
#include <algorithm>
#include <fstream>

// to spawn a process (hopefully)
#include<spawn.h>
#include<sys/wait.h>

#include <string>
#include <iostream>

#include "Dump.h"
#include "Client.h"
#include "Async_Bucket.h"

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;
extern bucket_t bucket;
int actionCounter;

uint8_t INPUT_BUFFER[INPUT_BUFFER_SIZE];
uint8_t OUTPUT_BUFFER[INPUT_BUFFER_SIZE];
Queue* inQueue;
bool status = false;
bool no_more_thread = false;

/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate
     * the input string to prevent buffer overflow.
     */
    printf("%s", str);
}

int initilize_ra() {

  // for the fucking remote attestation!
  // https://github.com/intel/sgx-ra-sample

  // other peoples with my problems:
  // https://software.intel.com/en-us/forums/intel-software-guard-extensions-intel-sgx/topic/814779

  bootSecureCommunication(global_eid);

  return 0;
}

int launch_enclave(sgx_launch_token_t* token, int* updated)
{

    pid_t pid;
    char s1 []= "startmotr.sh"; 
    char *sa1[]= {s1,NULL}; 

    std::string sgxmonitor_src(std::getenv("SGXMONITOR_PATH"));
    std::string full_path = sgxmonitor_src + "/src/stealthdb_toplaywith/startmotr.sh";

    int status_internal = posix_spawn(&pid,full_path.c_str(),NULL,NULL,sa1,NULL); 
    if (status_internal == 0) {
        printf("Child pid: %i\n", pid);
        if (waitpid(pid, &status_internal, 0) != -1) {
            printf("Child exited with status %i\n", status_internal);
        } else {
            perror("waitpid");
        }
    } else {
        printf("posix_spawn: %s\n", strerror(status_internal));
    }

    printf("INIT ENCLAVE TO PLAY WITH\n");
 
    
    // 0 -> single entries fashion
    if(initialize_client(0) < 0) {
      printf("Error init client\n");
      return -1;
    }

    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    ret = sgx_create_enclave(
        ENCLAVE_FILENAME, TRUE, token, updated, &global_eid, NULL);
        
    if (ret != SGX_SUCCESS)
        return ret;
    // else
    //     return 0;

    if(initilize_ra() < 0) {
      printf("Error init RA\n");
      return -1;
    }

    setActionCounter(global_eid, &actionCounter);
    setBucket(global_eid, &bucket);

    return 0;
}

int init()
{
    sgx_launch_token_t token = { 0 };
    int updated = 0;
    int resp = launch_enclave(&token, &updated);

    return resp;
}

// void *enclaveThread(void *) {
void enclaveThread()
{
    // if (no_more_thread)
    //     return;

    // printf("start thread\n");
    int resp = 0;
    enclaveProcess(global_eid, &resp, inQueue);
    // printf("stop thread\n");
}

int stopExtension() {

    printf("begin stopExtension\n");
    if (status)
    {
    //     request* req = new request;

    //     // memcpy(req->buffer, &pSrc, INT32_LENGTH);
    //     req->ocall_index = CMD_STOP_EXTENTION;
    //     req->is_done = -1;

    //     inQueue->enqueue(req);
    //     printf("begin loop\n");
    //     while (true)
    //     {
    //         if (req->is_done == -1)
    //         {
    //             printf("pause\n");
    //             __asm__("pause");
    //         }
    //         else
    //         {
    //             spin_unlock(&req->is_done);
    //             printf("break\n");
    //             break;
    //         }
    //     }
        printf("makeendmsg\n");
        makeEndMsg(global_eid);

        status = false;

        // no_more_thread = true;

        // printf("sgx_destroy_enclave\n");
        // sgx_destroy_enclave(global_eid);
        printf("return 0\n");
        return 0;
    }

    printf("return 1\n");
    return 1;
}

int initMultithreading()
{

    sgx_launch_token_t token = { 0 };
    int updated = 0;
    status = true;
    int ans = launch_enclave(&token, &updated);

    inQueue = new Queue();

    for (int i = 0; i < INPUT_BUFFER_SIZE; i++)
        INPUT_BUFFER[i] = OUTPUT_BUFFER[i] = 0;

    std::thread th = std::thread(&enclaveThread);

    th.detach();

    return ans;
}

int generateKey()
{
    if (!status)
    {
        int resp = initMultithreading();
        if (resp != SGX_SUCCESS)
            return resp;
    }

    int resp, resp_enclave, flength;
    uint8_t* sealed_key_b = new uint8_t[SEALED_KEY_LENGTH];

    std::fstream data_file;
    data_file.open(DATA_FILENAME,
                   std::fstream::in | std::fstream::out | std::fstream::binary);
    if (data_file)
    {
        data_file.seekg(0, data_file.end);
        flength = data_file.tellg();

        if (flength == SEALED_KEY_LENGTH)
            return 0;

        else
        {
            resp = generateKeyEnclave(
                global_eid, &resp_enclave, sealed_key_b, SEALED_KEY_LENGTH);
            if (resp != SGX_SUCCESS)
                return resp;
            data_file.write((char*)sealed_key_b, SEALED_KEY_LENGTH);
        }
    }
    else
        return NO_KEYS_STORAGE;

    data_file.close();
    delete[] sealed_key_b;

    return (int)flength / SEALED_KEY_LENGTH;
}

int loadKey(int item)
{
    if (!status)
    {
        int resp = initMultithreading();
        if (resp != SGX_SUCCESS)
            return resp;
    }
    int resp, resp_enclave;
    uint8_t sealed_key_b[SEALED_KEY_LENGTH];

    std::fstream data_file;
    data_file.open(DATA_FILENAME, std::fstream::in | std::fstream::binary);
    if (data_file)
    {
        data_file.seekg(0, data_file.end);
        int flength = data_file.tellg();
        if (flength < item * SEALED_KEY_LENGTH + SEALED_KEY_LENGTH)
            return NO_KEY_ID;

        data_file.seekg(item * SEALED_KEY_LENGTH);
        data_file.read((char*)sealed_key_b, SEALED_KEY_LENGTH);
        resp = loadKeyEnclave(
            global_eid, &resp_enclave, sealed_key_b, SEALED_KEY_LENGTH);
        if (resp != SGX_SUCCESS)
            return resp;
    }
    else
        return NO_KEYS_STORAGE;

    data_file.close();
    return 0;
}
