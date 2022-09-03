# StealthDB Macrobenchmark

This contains notes about macrobenchmarking PostgreSQL+StealthDB.

The tests are conducted with a scale factor that ranges from 10 to 100.

0. Drop existing test databse, if exists: `DROP DATABASE TEST;`
1. Create a test database: `CREATE DATABASE TEST;`
2. Init database with a given scale-factor (option `-s`): `pgbench -U test -i -s 10`
3. Fix database with encrypted fields: `psql -U postgres -d test -f ./fix_database.sql`
4. Run the benchmark, we use 1000 transactions (option `-t`): `pgbench -U test  -f stealthdb.sql -t 1000`

or else: just run `./run_benchmakr.ph` and hope it ends.