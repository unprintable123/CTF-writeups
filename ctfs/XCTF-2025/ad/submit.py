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
    stdout, stderr = p.communicate()
    if not quite:
        print(stdout)
        print(stderr)
    return stdout

while True:
    with ProcessPoolExecutor(max_workers=2) as executor:
        
        
        def run_file(file):
            print(f"Running solver: {file}")
            cmd = f"sage handle_one_task.py {file}"
            print(cmd)
            out = run_solver_instance(cmd)
            return out
        
        tasks = []
        for file in glob.glob("solve/*.py"):
            task = executor.submit(run_file, file)
            tasks.append((file, task))
        
        for file, task in tasks:
            output = task.result(timeout=300)
            output = output.split(b'--------------------------------')[-1]
            print(f"Output from {file}: {output.decode()}")

    time.sleep(53)


