#!/usr/bin/env python3

import psycopg2, subprocess, time, re, json, sys, argparse
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT

def runBenchmarkSgxMonitor(scale_factor, transactions, warmup):

    # kill postgres
    cmd_str = "sudo pkill -9 postgres"
    print(cmd_str)
    cmd = cmd_str.split(' ')
    result = subprocess.run(cmd)

    # start postgres
    cmd_str = "sudo service postgresql start"
    print(cmd_str)
    cmd = cmd_str.split(' ')
    result = subprocess.run(cmd)

    conn = psycopg2.connect("dbname='postgres' user='postgres' host='localhost' password='postgres'")
    conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT) 

    # 0. Drop existing test databse, if exists: `DROP DATABASE IF EXISTS TEST;`
    cur = conn.cursor()
    cur.execute("DROP DATABASE IF EXISTS TEST")

    # 0.1. Drop encdb extension `DROP EXTENSION IF EXISTS ENCDB CASCADE;`
    cur.execute("DROP EXTENSION IF EXISTS ENCDB CASCADE")

    # 1. Create a test database: `CREATE DATABASE TEST;`
    cur.execute("CREATE DATABASE TEST")

    conn.close ()

    # 2. Init database with a given scale-factor (option `-s`): `pgbench -U test -i -s 10`
    cmd_str = f"pgbench -U test -i -s {scale_factor}"
    print(cmd_str)
    cmd = cmd_str.split(' ')
    result = subprocess.run(cmd)

    # 3.0 start monitor
    cmd_str = "/home/flavio/SgxMonitor/src/monitor_batch/monitor"
    monitor_dir = "/home/flavio//SgxMonitor/src/monitor_batch/"
    print(cmd_str)
    cmd = cmd_str.split(' ')
    subprocess.Popen(cmd, shell=True, stdin=None, stdout=None, stderr=None, close_fds=True, cwd=monitor_dir)
    time.sleep(2)

    # 3.1 Fix database with encrypted fields: `psql -U postgres -d test -f ./fix_database.sql`
    cmd_str = "psql -U postgres -d test -f ./fix_database.sql"
    print(cmd_str)
    cmd = cmd_str.split(' ')
    result = subprocess.run(cmd)

    cmd_str = "sudo pkill -9 monitor"
    print(cmd_str)
    cmd = cmd_str.split(' ')
    result = subprocess.run(cmd)



    # # 4.0 start monitor
    # cmd_str = "/home/flavio/SgxMonitor/src/monitor_batch/monitor"
    # monitor_dir = "/home/flavio//SgxMonitor/src/monitor_batch/"
    # print(cmd_str)
    # cmd = cmd_str.split(' ')
    # subprocess.Popen(cmd, shell=True, stdin=None, stdout=None, stderr=None, close_fds=True, cwd=monitor_dir)
    # time.sleep(2)

    # # 4. Run the benchmark, we use 1000 transactions (option `-t`): `pgbench -U test  -f stealthdb.sql -t 1000`
    # cmd_str = f"pgbench -U test -s {scale_factor} -f stealthdb.sql -t {warmup}"
    # print(cmd_str)
    # cmd = cmd_str.split(' ')
    # result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # my_output = result.stdout.decode('utf-8')

    # cmd_str = "sudo pkill -9 monitor"
    # print(cmd_str)
    # cmd = cmd_str.split(' ')
    # result = subprocess.run(cmd)

    # 4.0 start monitor
    cmd_str = "/home/flavio/SgxMonitor/src/monitor_batch/monitor"
    monitor_dir = "/home/flavio//SgxMonitor/src/monitor_batch/"
    print(cmd_str)
    cmd = cmd_str.split(' ')
    subprocess.Popen(cmd, shell=True, stdin=None, stdout=None, stderr=None, close_fds=True, cwd=monitor_dir)
    time.sleep(2)


    # 4. Run the benchmark, we use 1000 transactions (option `-t`): `pgbench -U test  -f stealthdb.sql -t 1000`
    cmd_str = f"pgbench -U test -s {scale_factor} -f stealthdb.sql -t {transactions}"
    print(cmd_str)
    cmd = cmd_str.split(' ')
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    my_output = result.stdout.decode('utf-8')

    print(my_output)

    latency_average = re.findall(r'latency average = (\d+.\d+) ms', my_output)[0]
    tps_wconn = re.findall(r'tps = (\d+.\d+) \(including connections establishing\)', my_output)[0]
    tps_woconn = re.findall(r'tps = (\d+.\d+) \(excluding connections establishing\)', my_output)[0]
    
    cmd_str = "sudo pkill -9 monitor"
    print(cmd_str)
    cmd = cmd_str.split(' ')
    result = subprocess.run(cmd)


    return (latency_average, tps_wconn, tps_woconn)

def runBenchmarkVanilla(scale_factor, transactions, warmup):
    
    # kill postgres
    cmd_str = "sudo pkill -9 postgres"
    print(cmd_str)
    cmd = cmd_str.split(' ')
    result = subprocess.run(cmd)

    # start postgres
    cmd_str = "sudo service postgresql start"
    print(cmd_str)
    cmd = cmd_str.split(' ')
    result = subprocess.run(cmd)

    conn = psycopg2.connect("dbname='postgres' user='postgres' host='localhost' password='postgres'")
    conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT) 

    # 0. Drop existing test databse, if exists: `DROP DATABASE IF EXISTS TEST;`
    cur = conn.cursor()
    cur.execute("DROP DATABASE IF EXISTS TEST")

    # 0.1. Drop encdb extension `DROP EXTENSION IF EXISTS ENCDB CASCADE;`
    cur.execute("DROP EXTENSION IF EXISTS ENCDB CASCADE")

    # 1. Create a test database: `CREATE DATABASE TEST;`
    cur.execute("CREATE DATABASE TEST")

    conn.close ()

    # 2. Init database with a given scale-factor (option `-s`): `pgbench -U test -i -s 10`
    cmd_str = f"pgbench -U test -i -s {scale_factor}"
    print(cmd_str)
    cmd = cmd_str.split(' ')
    result = subprocess.run(cmd)

    # 3 Fix database with encrypted fields: `psql -U postgres -d test -f ./fix_database.sql`
    cmd_str = "psql -U postgres -d test -f ./fix_database.sql"
    print(cmd_str)
    cmd = cmd_str.split(' ')
    result = subprocess.run(cmd)



    # # 4. Run the benchmark, we use 1000 transactions (option `-t`): `pgbench -U test  -f stealthdb.sql -t 1000`
    # cmd_str = f"pgbench -U test -s {scale_factor} -f stealthdb.sql -t {warmup}"
    # print(cmd_str)
    # cmd = cmd_str.split(' ')
    # result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # my_output = result.stdout.decode('utf-8')



    # 4. Run the benchmark, we use 1000 transactions (option `-t`): `pgbench -U test  -f stealthdb.sql -t 1000`
    cmd_str = f"pgbench -U test -s {scale_factor} -f stealthdb.sql -t {transactions}"
    print(cmd_str)
    cmd = cmd_str.split(' ')
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    my_output = result.stdout.decode('utf-8')

    print(my_output)

    latency_average = re.findall(r'latency average = (\d+.\d+) ms', my_output)[0]
    tps_wconn = re.findall(r'tps = (\d+.\d+) \(including connections establishing\)', my_output)[0]
    tps_woconn = re.findall(r'tps = (\d+.\d+) \(excluding connections establishing\)', my_output)[0]
    
    return (latency_average, tps_wconn, tps_woconn)

def installEncdbSgxMonitor():
    cmd_str = "sudo make install"
    print(cmd_str)
    cmd = cmd_str.split(' ')
    result = subprocess.run(cmd, cwd="/home/flavio/SgxMonitor/src/stealthdb_toplaywith/")

def installEncdbVanilla():
    cmd_str = "sudo make install"
    print(cmd_str)
    cmd = cmd_str.split(' ')
    result = subprocess.run(cmd, cwd="/home/flavio/SgxMonitor/src/stealthdb_vanilla/")

def main():


    parser = argparse.ArgumentParser()
    parser.add_argument('--output', '-o', required=True, type=str, help='The macrobenchmakr output', default='macrobenchmark_stealthdb.json')

    args = parser.parse_args()

    output_banchmark = args.output
    

    # SCALE_FACTOR = 10
    WARMUP = 1000
    TRANSACTIONS = 5000

    MIN_SCALEFACTOR = 10
    MAX_SCALEFACTOR = 110

    results = {}

    installEncdbSgxMonitor()

    tag = "SgxMonitor"
    for s in range(MIN_SCALEFACTOR, MAX_SCALEFACTOR, 10):
        print(f"{tag} {s}")

        r = runBenchmarkSgxMonitor(s, TRANSACTIONS, WARMUP)
        x = results.get(tag, [])
        x.append([s, r])

        results[tag] = x

    installEncdbVanilla()

    tag = "Vanilla"
    for s in range(MIN_SCALEFACTOR, MAX_SCALEFACTOR, 10):
        print(f"{tag} {s}")

        r = runBenchmarkVanilla(s, TRANSACTIONS, WARMUP)
        x = results.get(tag, [])
        x.append([s, r])

        results[tag] = x

    print(results)
    with open(output_banchmark, "w") as f:
        json.dump(results, f)

if __name__ == "__main__":
    main()
