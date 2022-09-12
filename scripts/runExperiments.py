#!/usr/bin/python3

import sys, os, argparse, subprocess, time, psutil

HOME_SGXMONITOR = os.getenv('SGXMONITOR_PATH')

# monitor paths
MONITOR_BATCH_DIR = os.path.join(HOME_SGXMONITOR, 'src', 'monitor_batch')
MONITOR_BATCH = os.path.join(MONITOR_BATCH_DIR, 'monitor')
MONITOR_LENGTH_DIR  = os.path.join(HOME_SGXMONITOR, 'src', 'monitor_length')
MONITOR_LENGTH = os.path.join(MONITOR_LENGTH_DIR, 'monitor')

# custom paths
CUSTOM_VANILLA_DIR = os.path.join(HOME_SGXMONITOR, 'src', 'custom_vanilla')
CUSTOM_VANILLA = os.path.join(CUSTOM_VANILLA_DIR, 'app')
CUSTOM_TRACED_BATCH_DIR = os.path.join(HOME_SGXMONITOR, 'src', 'custom_traced_batch')
CUSTOM_TRACED_BATCH = os.path.join(CUSTOM_TRACED_BATCH_DIR, 'app')
CUSTOM_TRACED_LENGTH_DIR = os.path.join(HOME_SGXMONITOR, 'src', 'custom_traced_length')
CUSTOM_TRACED_LENGTH = os.path.join(CUSTOM_TRACED_LENGTH_DIR, 'app')

# contact paths
CONTACT_TRACED_BATCH_DIR = os.path.join(HOME_SGXMONITOR, 'src', 'contact_traced_batch')
CONTACT_TRACED_BATCH = os.path.join(CONTACT_TRACED_BATCH_DIR, 'app')
CONTACT_TRACED_LENGTH_DIR = os.path.join(HOME_SGXMONITOR, 'src', 'contact_traced_length')
CONTACT_TRACED_LENGTH = os.path.join(CONTACT_TRACED_LENGTH_DIR, 'app')
CONTACT_VANILLA_DIR = os.path.join(HOME_SGXMONITOR, 'src', 'contact_vanilla')
CONTACT_VANILLA = os.path.join(CONTACT_VANILLA_DIR, 'app')

# sgx-biniax2 paths
SGXBINIAX2_VANILLA_DIR = os.path.join(HOME_SGXMONITOR, 'src', 'sgx-biniax2_vanilla')
SGXBINIAX2_VANILLA = os.path.join(SGXBINIAX2_VANILLA_DIR, 'app')
SGXBINIAX2_TRACED_BATCH_DIR = os.path.join(HOME_SGXMONITOR, 'src', 'sgx-biniax2_traced_batch')
SGXBINIAX2_TRACED_BATCH = os.path.join(SGXBINIAX2_TRACED_BATCH_DIR, 'app')
SGXBINIAX2_TRACED_LENGTH_DIR = os.path.join(HOME_SGXMONITOR, 'src', 'sgx-biniax2_traced_length')
SGXBINIAX2_TRACED_LENGTH = os.path.join(SGXBINIAX2_TRACED_LENGTH_DIR, 'app')

# stealthdb paths
STEALTHDB_VANILLA_DIR_BASE = os.path.join(HOME_SGXMONITOR, 'src', 'stealthdb_vanilla')
STEALTHDB_VANILLA_DIR = os.path.join(STEALTHDB_VANILLA_DIR_BASE, 'src', 'microbenchmark')
STEALTHDB_VANILLA = os.path.join(STEALTHDB_VANILLA_DIR, 'app')
STEALTHDB_TRACED_TOPLAYWITH_DIR_BASE = os.path.join(HOME_SGXMONITOR, 'src', 'stealthdb_toplaywith')
STEALTHDB_TRACED_BATCH_DIR = os.path.join(STEALTHDB_TRACED_TOPLAYWITH_DIR_BASE, 'src', 'microbenchmark_batch')
STEALTHDB_TRACED_BATCH = os.path.join(STEALTHDB_TRACED_BATCH_DIR, 'app')
STEALTHDB_TRACED_LENGTH_DIR = os.path.join(STEALTHDB_TRACED_TOPLAYWITH_DIR_BASE, 'src', 'microbenchmark_length')
STEALTHDB_TRACED_LENGTH = os.path.join(STEALTHDB_TRACED_LENGTH_DIR, 'app')


def runBenchmark(monitor, monitor_dir, tracer, tracer_dir):
    if monitor:
        subprocess.Popen([monitor], shell=True, stdin=None, stdout=None, stderr=None, close_fds=True, cwd=monitor_dir)
        time.sleep(2)
    subprocess.Popen([tracer], cwd=tracer_dir)
    
    time.sleep(2)

    while "monitor" in [p.name() for p in psutil.process_iter()]:
        # monitor active but not app running, kill the monitor
        print("[INFO] wait! monitor is still running, don't Ctrl+C pls")
        pp_app = [p for p in psutil.process_iter() if p.name() == "app"]
        pp_mon = [p for p in psutil.process_iter() if p.name() == "monitor"]
        if any([pp.status() == 'zombie' for pp in pp_app]):
            for p in pp_mon:
                p.kill()
            for p in pp_app:
                p.kill()

        time.sleep(10)


def str2bool(v):
    if isinstance(v, bool):
       return v
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')

def installEncdbSgxMonitor():
    if os.geteuid() == 0:
        cmd_str = "make install"
    else:
        cmd_str = "sudo make install"
    print(cmd_str)
    cmd = cmd_str.split(' ')
    result = subprocess.run(cmd, cwd=STEALTHDB_TRACED_TOPLAYWITH_DIR_BASE)

def installEncdbVanilla():
    if os.geteuid() == 0:
        cmd_str = "make install"
    else:
        cmd_str = "sudo make install"
    print(cmd_str)
    cmd = cmd_str.split(' ')
    result = subprocess.run(cmd, cwd=STEALTHDB_VANILLA_DIR_BASE)

def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('--overwrite', '-o', type=str2bool, nargs='?', const=True, default=False,help='Shold I overwrite the previous benchmark?')
    parser.add_argument('--benchmarkfile', '-b', required=False, type=str, help='The benchmark file where to store results', default='../benchmark.txt')

    args = parser.parse_args()

    benchmarkfile = args.benchmarkfile
    overwrite = args.overwrite

    if os.path.isfile(benchmarkfile) and not overwrite:
        print("Benchmar file already exists [{}]".format(benchmarkfile))
        exit(1)

    if os.path.isfile(benchmarkfile) and overwrite:
        os.remove(benchmarkfile)

    print("Now I run the microbenchmark")

    # custom
    runBenchmark(None, None, CUSTOM_VANILLA, CUSTOM_VANILLA_DIR)
    runBenchmark(MONITOR_BATCH, MONITOR_BATCH_DIR, CUSTOM_TRACED_BATCH, CUSTOM_TRACED_BATCH_DIR)
    runBenchmark(MONITOR_LENGTH, MONITOR_LENGTH_DIR, CUSTOM_TRACED_LENGTH, CUSTOM_TRACED_LENGTH_DIR)

    # contact
    runBenchmark(None, None, CONTACT_VANILLA, CONTACT_VANILLA_DIR)
    runBenchmark(MONITOR_BATCH, MONITOR_BATCH_DIR, CONTACT_TRACED_BATCH, CONTACT_TRACED_BATCH_DIR)
    runBenchmark(MONITOR_LENGTH, MONITOR_LENGTH_DIR, CONTACT_TRACED_LENGTH, CONTACT_TRACED_LENGTH_DIR)

    # sgx-biniax2
    runBenchmark(None, None, SGXBINIAX2_VANILLA, SGXBINIAX2_VANILLA_DIR)
    runBenchmark(MONITOR_BATCH, MONITOR_BATCH_DIR, SGXBINIAX2_TRACED_BATCH, SGXBINIAX2_TRACED_BATCH_DIR)
    runBenchmark(MONITOR_LENGTH, MONITOR_LENGTH_DIR, SGXBINIAX2_TRACED_LENGTH, SGXBINIAX2_TRACED_LENGTH_DIR)

    # steathdb
    installEncdbVanilla()
    runBenchmark(None, None, STEALTHDB_VANILLA, STEALTHDB_VANILLA_DIR)
    installEncdbSgxMonitor()
    runBenchmark(MONITOR_BATCH, MONITOR_BATCH_DIR, STEALTHDB_TRACED_BATCH, STEALTHDB_TRACED_BATCH_DIR)
    runBenchmark(MONITOR_LENGTH, MONITOR_LENGTH_DIR, STEALTHDB_TRACED_LENGTH, STEALTHDB_TRACED_LENGTH_DIR)



if __name__ == "__main__":
  main()
