#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"
#include <stdio.h>
#include <errno.h>
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


sgx_enclave_id_t eid;

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
	
int destroyEnclave(sgx_enclave_id_t eid){
	if(SGX_SUCCESS != sgx_destroy_enclave(eid))
		return -1;
	return 0;
}

void init_enclave(void){
	eid = createEnclave();
}

void bridge_init_store(){
	init_store(eid);
}

void bridge_free_store(){
	free_store(eid);
}

void bridge_add_to_store(const void *bytes, size_t len){
	add_to_store(eid,bytes,len);
}

void bridge_get_from_store(uint8_t *out_var,size_t len,uint16_t index){
	get_from_store(eid,out_var,len,index);
}

void bridge_encrypt_store(const char* fname){
	encrypt_store(eid, fname);
}

void bridge_decrypt_store(uint8_t *ebytes, size_t len){
	decrypt_store(eid,ebytes,len);
}
