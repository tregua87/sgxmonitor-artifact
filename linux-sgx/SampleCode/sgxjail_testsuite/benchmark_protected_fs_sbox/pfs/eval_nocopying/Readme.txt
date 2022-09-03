The 'normal' csv was compiled normally.
The 'nocopying' csv was modified as follows:
In enclave_u.c we changed the ocall
  `host_u_sgxprotectedfs_fwrite_node`
by replacing
  `memcpy((void*)_in_buffer, _tmp_buffer, _len_buffer);`
with 
  `memcpy((void*)_in_buffer, _tmp_buffer, 0);`

To do this, follow these steps:
1. Compile normally
2. Make modifications to Enclave_u.c as outlined above
3. Replace the Makefile with the one in this directory.
   This prevents re-creation of Enclave_u.c
4. Compile
