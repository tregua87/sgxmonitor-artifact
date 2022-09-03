\set aid random(1, 100000 * :scale)
\set bid random(1, 1 * :scale)
\set tid random(1, 10 * :scale)
\set delta random(-5000, 5000)
BEGIN;
--UPDATE pgbench_accounts SET abalance = abalance + :delta WHERE aid = :aid;
UPDATE pgbench_accounts SET abalance = abalance + pg_enc_int4_encrypt(:delta) WHERE aid = :aid;
SELECT abalance FROM pgbench_accounts WHERE aid = :aid;
UPDATE pgbench_tellers SET tbalance = tbalance + pg_enc_int4_encrypt(:delta) WHERE tid = :tid;
UPDATE pgbench_branches SET bbalance = bbalance + pg_enc_int4_encrypt(:delta) WHERE bid = :bid;
INSERT INTO pgbench_history (tid, bid, aid, delta, mtime) VALUES (:tid, :bid, :aid, pg_enc_int4_encrypt(:delta), CURRENT_TIMESTAMP);
END;
