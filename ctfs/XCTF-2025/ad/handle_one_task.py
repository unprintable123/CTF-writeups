import requests
import threading
import random
import string
import time
import sys, os, glob
from concurrent.futures import ProcessPoolExecutor
import subprocess, re

API_URL = "http://174.35.3.250/api/ct/web/awd_race/race/b2a01b4b88df2f76b05bbc1e4e50b2f7/flag/robot/"
TOKEN = "f330700f0498bdc5a265c716b9f61b0e"
HEADERS = {"Content-Type": "application/json"}

REMOTE_ADDR = "conn"
EXPLOIT_TIMEOUT = 30
RECV_TIMEOUT = 2
def submit_flag(flag: str) -> dict:
    payload = {"flag": flag, "token": TOKEN}
    try:
        r = requests.post(API_URL, headers=HEADERS, json=payload, timeout=10)
        try:
            data = r.json()
            print(data)
        except Exception:
            print({"status_code": r.status_code, "text": r.text})
    except Exception as e:
        print({"error": str(e)})

def run_solver_instance(cmd, quite=True):
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate(timeout=60)
    if not quite:
        print(stdout)
        print(stderr)
    return stdout

import sys
file = sys.argv[1]

print(f"Running solver: {file}")
task = os.path.basename(file).split("_",1)[0]
if task == "bnote":
    ip = '173.30.4.'
elif task == "somehash":
    ip = '173.30.1.'
elif task == "someheap":
    ip = '173.30.2.'
elif task == "nsl":
    ip = '173.30.3.'
else:
    raise Exception(f"Unknown task for file {file}, skipping.")

with ProcessPoolExecutor(max_workers=12) as executor:
    def attack_ip(i):
        full_ip = ip + str(i)
        cmd = f"sage {file} {full_ip}"
        print(cmd)
        out = run_solver_instance(cmd)
        maybe_flag = re.search(r'flag\{[a-f0-9]*\}', out.decode())
        # print(f"Output from {full_ip}: {out.decode()}")
        flag = ""
        if maybe_flag:
            flag = maybe_flag.group(0)
            print(f"Found flag from {full_ip}: {flag}")
            submit_flag(flag)
        return out, flag
    
    tasks = [executor.submit(attack_ip, i) for i in range(10, 40)]
    time.sleep(4)
    print("--------------------------------")
    for ip, task in zip(range(10, 40), tasks):
        try:
            output = task.result()
            print(f"Completed attack on {ip}, flag: {output[1]}")
            # print(output[0].decode())
        except Exception as e:
            print(f"Error attacking {ip}: {e}")


