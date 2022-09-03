#!/usr/bin/python3

import sys, json, statistics

fPath = sys.argv[1]

with open(fPath, 'r') as f:
    r = json.load(f)

    enclave_init = r["SgxMonitor"][0]
    game_init = r["SgxMonitor"][1]

    sgxmonitor_enclave_init_avg = sum(enclave_init) / len(enclave_init)
    sgxmonitor_enclave_init_stdev = statistics.stdev(enclave_init)

    sgxmonitor_game_init_avg = sum(game_init) / len(game_init)
    sgxmonitor_game_init_stdev = statistics.stdev(game_init)
    
    print("SgxMonitor:")
    print(f"Enclave Init: {sgxmonitor_enclave_init_avg} {sgxmonitor_enclave_init_stdev}")
    print(f"Game Init: {sgxmonitor_game_init_avg} {sgxmonitor_game_init_stdev}")

    enclave_init = r["Vanilla"][0]
    game_init = r["Vanilla"][1]

    vanilla_enclave_init_avg = sum(enclave_init) / len(enclave_init)
    vanilla_enclave_init_stdev = statistics.stdev(enclave_init)

    vanilla_game_init_avg = sum(game_init) / len(game_init)
    vanilla_game_init_stdev = statistics.stdev(game_init)

    print("-"*20)
    
    print("Vanilla:")
    print(f"Enclave Init: {vanilla_enclave_init_avg} {vanilla_enclave_init_stdev}")
    print(f"Game Init: {vanilla_game_init_avg} {vanilla_game_init_stdev}")

    print("-"*20)

    print(f"Enclave Init SgxMonitor vs Vanilla: {sgxmonitor_enclave_init_avg/vanilla_enclave_init_avg}")
    print(f"Game Init SgxMonitor vs Vanilla: {sgxmonitor_game_init_avg/vanilla_game_init_avg}")

    print(f"Enclave Init SgxMonitor vs Vanilla: {(sgxmonitor_game_init_avg-sgxmonitor_enclave_init_avg)/(vanilla_game_init_avg-vanilla_enclave_init_avg)}")