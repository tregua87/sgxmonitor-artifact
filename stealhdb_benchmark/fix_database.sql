CREATE EXTENSION encdb;
ALTER TABLE pgbench_accounts ALTER COLUMN abalance TYPE enc_int4  USING pg_enc_int4_encrypt(abalance);
ALTER TABLE pgbench_branches ALTER COLUMN bbalance TYPE enc_int4  USING pg_enc_int4_encrypt(bbalance);
ALTER TABLE pgbench_history ALTER COLUMN delta TYPE enc_int4  USING pg_enc_int4_encrypt(delta);
ALTER TABLE pgbench_tellers ALTER COLUMN tbalance TYPE enc_int4  USING pg_enc_int4_encrypt(tbalance);