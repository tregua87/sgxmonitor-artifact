#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"
#include <stdio.h>
#include <errno.h>

#include "Utility.h"
#include "Dump.h"
#include "Client.h"

#include "Async_Bucket.h"
#include <pthread.h>

#define MODE "traced_length"

//#define ENCLAVE_FILE "Debug/BiniaxEnclave.signed.dll"
# define ENCLAVE_FILE "enclave.signed.so"
#define MAX_BUF_LEN  100

//For some reason this doesn't match the linkage specification,
//EVEN THOUGH IT MATCHES EXACTLY.
//I had to delete the definition of this in the header file...
void ocall_write_resource(const char *str, const void *bytes, size_t len){
	FILE *outfile = fopen(str,"wb");
	fwrite(&len,sizeof(uint32_t),1,outfile);
	fwrite(bytes, sizeof(uint8_t), len, outfile);
	fclose(outfile);
}

void ocall_write_out(const void *bytes, size_t len){
	FILE *outfile = fopen("blob.txt","wb");
	fwrite(&len,sizeof(len),1,outfile);
	fwrite(bytes, sizeof(uint8_t), len, outfile);
	fclose(outfile);
}

void ocall_print_raw(const void *bytes, size_t len){
	FILE *outfile = fopen("raw_bytes.txt","wb");
	fwrite(&len,sizeof(len),1,outfile);
	fwrite(bytes, sizeof(uint8_t), len, outfile);
	fclose(outfile);
	/*uint8_t *b = (uint8_t *)bytes;
	for( int i = 0; i < len; i++ ){
		printf("%u",b[i]);
	}*/
}

/* OCall functions */
void ocall_print_string(const char *str)
{
    printf("%s", str);
}


sgx_enclave_id_t eid = 0;
extern bucket_t bucket;
int actionCounter;

int initilize_ra() {

  // for the fucking remote attestation!
  // https://github.com/intel/sgx-ra-sample

  // other peoples with my problems:
  // https://software.intel.com/en-us/forums/intel-software-guard-extensions-intel-sgx/topic/814779

  bootSecureCommunication(eid);

  return 0;
}

sgx_enclave_id_t createEnclave()
{
	sgx_enclave_id_t   eid;
	sgx_status_t       ret   = SGX_SUCCESS;
	sgx_launch_token_t token = {0};
	int testingdebugval = SGX_DEBUG_FLAG;
	int updated = 0;
	ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, 
							 &eid, NULL);
	if (ret != SGX_SUCCESS) {
		printf("App: error %#x, failed to create enclave.\n", ret);
		return -1;
	}
	return eid;
}

void init_enclave(void){

	// 0 -> single entries fashion
    if(initialize_client(1) < 0) {
      printf("Enter a character before exit ...\n");
      getchar();
      exit(1);
    }

	eid = createEnclave();

	if(initilize_ra() < 0) {
      printf("Enter a character before exit ...\n");
      getchar();
      exit(1);
    }

	setActionCounter(eid, &actionCounter);
    setBucket(eid, &bucket);
}

int main(int argc, char** argv) {


	init_enclave();

	char bytes_in[MAX_BUF_LEN];
	memset(bytes_in, MAX_BUF_LEN, 0xAA);
	char bytes_out[MAX_BUF_LEN];

	unsigned char afile_bin[] = {
		0x7e, 0x00, 0x00, 0x00, 0x4c, 0x9c, 0x6c, 0x46, 0xd7, 0x83, 0x57, 0x67,
		0x42, 0x4a, 0x86, 0xf4, 0xc9, 0xa5, 0x97, 0xa8, 0x9d, 0x72, 0xf4, 0x2a,
		0xdb, 0xa4, 0xf4, 0x08, 0xd1, 0x4a, 0x57, 0xa5, 0xb9, 0x5e, 0xbd, 0x24,
		0xf4, 0xed, 0x66, 0xa4, 0xae, 0xd6, 0xea, 0x7b, 0xb9, 0x6c, 0xf9, 0x8f,
		0x9b, 0xb2, 0xd1, 0x80, 0x8f, 0x42, 0x1e, 0x38, 0x34, 0x78, 0x45, 0xc4,
		0x1d, 0x58, 0xb8, 0x9f, 0x50, 0x11, 0xd7, 0x4c, 0x28, 0xbb, 0x60, 0xba,
		0x7f, 0xed, 0x0f, 0xc2, 0x51, 0x27, 0x57, 0xe9, 0x7b, 0xaf, 0x95, 0xb7,
		0x59, 0x14, 0x58, 0x22, 0x88, 0xd1, 0x9a, 0xb1, 0xe6, 0xe4, 0xf5, 0x56,
		0x6b, 0x80, 0x7b, 0x25, 0x33, 0x6c, 0xb8, 0x05, 0xbe, 0xc5, 0x4c, 0x0d,
		0x23, 0xcb, 0xc5, 0x46, 0xb2, 0xf5, 0xc8, 0xc0, 0x4d, 0x99, 0xb1, 0xaf,
		0x1d, 0x7b, 0x9c, 0x64, 0xa7, 0x2c, 0x90, 0x9c, 0xa0, 0xa1
	};
	unsigned int afile_bin_len = 130; 

	printf("[INFO] Start warmup!\n");


	init_store(eid);
	dumpLen(MODE, "init_store", &actionCounter);
	add_to_store(eid, bytes_in, MAX_BUF_LEN);
	dumpLen(MODE, "add_to_store", &actionCounter);
	get_from_store(eid, bytes_out, MAX_BUF_LEN, 0);
	dumpLen(MODE, "get_from_store", &actionCounter);
	encrypt_store(eid, "afile.bin");
	dumpLen(MODE, "encrypt_store", &actionCounter);
	decrypt_store(eid, afile_bin, afile_bin_len);
	dumpLen(MODE, "decrypt_store", &actionCounter);
	free_store(eid);
	dumpLen(MODE, "free_store", &actionCounter);
	store_to_bytes(eid);
	dumpLen(MODE, "store_to_bytes", &actionCounter);

    printf("[INFO] sgx-biniax2 successfully returned.\n");

	makeEndMsg(eid);

	if(SGX_SUCCESS != sgx_destroy_enclave(eid))
		return -1;
	return 0;

	return 0;
}
