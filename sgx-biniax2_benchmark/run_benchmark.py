#!/usr/bin/env python3

import subprocess, time, re, json, sys, argparse

def runBenchmarkSgxMonitor(iteration):

    enclave_init = []
    game_init = []

    for i in range(iteration):

        cmd_str = "/home/flavio/SgxMonitor/src/monitor_batch/monitor"
        monitor_dir = "/home/flavio//SgxMonitor/src/monitor_batch/"
        print(cmd_str)
        cmd = cmd_str.split(' ')
        subprocess.Popen(cmd, shell=True, stdin=None, stdout=None, stderr=None, close_fds=True, cwd=monitor_dir)
        time.sleep(2)


        cmd_str = "./app"
        # print(cmd_str)
        # cmd = cmd_str.split(' ')
        # result = subprocess.run(cmd, cwd="/home/flavio/SgxMonitor/src/sgx-biniax2_vanilla")
        print(cmd_str)
        cmd = cmd_str.split(' ')
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, cwd="/home/flavio/SgxMonitor/src/sgx-biniax2_traced_toplaywith")
        # time.sleep(2)

        try:
            time.sleep(5)
            # resp = urllib.request.urlopen('http://localhost:8070')
            # assert b'Directory listing' in resp.read()
        finally:
            proc.terminate()
            try:
                my_output, _ = proc.communicate(timeout=0.2)
                # print('== subprocess exited with rc =', proc.returncode)

                my_output = my_output.decode('utf-8')

                # print(my_output)
            except subprocess.TimeoutExpired:
                print('subprocess did not terminate in time')


        # my_output = result.stdout.decode('utf-8')

        print(my_output)

        x = re.findall(r'Time elapsed in enclave initialization: (\d+) seconds, (\d+) nanoseconds', my_output)[0]

        a = int(x[0])
        b = int(x[1])

        enclave_init += [a*(10**9) + b]

        x = re.findall(r'Time elapsed in initialization: (\d+) seconds, (\d+) nanoseconds', my_output)[0]

        a = int(x[0])
        b = int(x[1])

        game_init += [a*(10**9) + b]

        cmd_str = "sudo pkill -9 monitor"
        print(cmd_str)
        cmd = cmd_str.split(' ')
        result = subprocess.run(cmd)

    return (enclave_init, game_init)

def runBenchmarkVanilla(iteration):

    enclave_init = []
    game_init = []

    for i in range(iteration):
        cmd_str = "./app"
        # print(cmd_str)
        # cmd = cmd_str.split(' ')
        # result = subprocess.run(cmd, cwd="/home/flavio/SgxMonitor/src/sgx-biniax2_vanilla")
        print(cmd_str)
        cmd = cmd_str.split(' ')
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, cwd="/home/flavio/SgxMonitor/src/sgx-biniax2_vanilla")
        # time.sleep(2)

        try:
            time.sleep(5)
            # resp = urllib.request.urlopen('http://localhost:8070')
            # assert b'Directory listing' in resp.read()
        finally:
            proc.terminate()
            try:
                my_output, _ = proc.communicate(timeout=0.2)
                # print('== subprocess exited with rc =', proc.returncode)

                my_output = my_output.decode('utf-8')

                # print(my_output)
            except subprocess.TimeoutExpired:
                print('subprocess did not terminate in time')


        # my_output = result.stdout.decode('utf-8')

        print(my_output)

        x = re.findall(r'Time elapsed in enclave initialization: (\d+) seconds, (\d+) nanoseconds', my_output)[0]

        a = int(x[0])
        b = int(x[1])

        enclave_init += [a*(10**9) + b]

        x = re.findall(r'Time elapsed in initialization: (\d+) seconds, (\d+) nanoseconds', my_output)[0]

        a = int(x[0])
        b = int(x[1])

        game_init += [a*(10**9) + b]

    return (enclave_init, game_init)


def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('--output', '-o', required=True, type=str, help='The macrobenchmakr output', default='macrobenchmark_sgx-biniax2.json')

    args = parser.parse_args()

    output_banchmark = args.output

    NUMBER_OF_ITERATION = 10

    results = {}

    results["Vanilla"] = runBenchmarkVanilla(NUMBER_OF_ITERATION)
    results["SgxMonitor"] = runBenchmarkSgxMonitor(NUMBER_OF_ITERATION)

    print(results)
    with open(output_banchmark, "w") as f:
        json.dump(results, f)

if __name__ == "__main__":
    main()
