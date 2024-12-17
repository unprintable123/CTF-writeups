from sage.all import *
import requests
import math
import time
import json
import string
import random
import os

def flatter(M):
    from subprocess import check_output
    from re import findall
    z = "[[" + "]\n[".join(" ".join(map(str, row)) for row in M) + "]]"
    ret = check_output(["flatter"], input=z.encode())
    return matrix(M.nrows(), M.ncols(), map(int, findall(b"-?\\d+", ret)))

url = "http://34.146.145.253:42001/"

positions = {
    "user": [3861, -67500, 50947],
    "sat0": [67749, 27294, 94409],
    "sat1": [38630, -52128, -9112],
    "sat2": [-86459, -74172, 8698],
    "sat3": [36173, -84060, 95354],
    "flag": [0,0,0]
}
valid_chars = set(string.printable[:-5])

def my_decoder(hex_data):
    str_data = bytes.fromhex(hex_data).decode('utf-8',errors = 'ignore')
    #trim illegal characters
    str_data = ''.join(filter(lambda x: x in valid_chars, str_data))
    return str_data

def distance(a,b):
    dist = 0
    for i in range(3):
        dist += (a[i]-b[i])**2
    return math.sqrt(dist)


def forge_sign(id):
    ret = requests.get(f"http://34.146.145.253:42001/sat{id}")
    sign = ret.json()
    data = sign["data"]
    n = sign["public_key"]["n"]
    sign = sign["sign"]
    
    s = int.from_bytes(bytes.fromhex(sign), 'little')
    plain = int.from_bytes(bytes.fromhex(data), 'little')
    assert pow(s, 65537, n) == plain
    ut = time.time()
    forge_target0 = json.dumps({"time": int(ut) - int(distance(positions[f"sat{id}"], positions["flag"])),"something":"test"}).encode()
    forge_target = forge_target0.replace(b"test", b"\x00"*128)
    # print(forge_target)
    base = int.from_bytes(forge_target, 'little')
    re = (plain-base) * pow(2, -35*8, n) % n
    forge_target2 = forge_target0.replace(b"test", re.to_bytes(128, 'little'))
    while b'"' in re.to_bytes(128, 'little'):
        s = random.randint(1, n)
        plain = pow(s, 65537, n)
        re = (plain-base) * pow(2, -35*8, n) % n
        forge_target2 = forge_target0.replace(b"test", re.to_bytes(128, 'little'))
    print(my_decoder(forge_target2.hex()))
    assert (int.from_bytes(forge_target2, 'little')-plain)%n == 0
    return {
        "data": forge_target2.hex(),
        "sign": s.to_bytes(128,'little').hex()
    }

def is_in_area(data):
    try:
        ut = time.time()
        data_sat0 = json.loads(my_decoder(data.sat0["data"]))
        data_sat1 = json.loads(my_decoder(data.sat1["data"]))
        data_sat2 = json.loads(my_decoder(data.sat2["data"]))
        data_sat3 = json.loads(my_decoder(data.sat3["data"]))
        if (-1 <= (ut - data_sat0["time"]) - distance(positions["sat0"],positions["flag"]) <= 20) and (-1 <= (ut - data_sat1["time"]) - distance(positions["sat1"],positions["flag"]) <= 20) and (-1 <= (ut - data_sat2["time"]) - distance(positions["sat2"],positions["flag"]) <= 20) and (-1 <= (ut - data_sat3["time"]) - distance(positions["sat3"],positions["flag"]) <= 20):
            return True
        else:
            return False
    except:
        return False

sat0 = forge_sign(0)
sat1 = forge_sign(1)
sat2 = forge_sign(2)
sat3 = forge_sign(3)


ret = requests.post("http://34.146.145.253:42001/auth", json={"sat0": sat0, "sat1": sat1, "sat2": sat2, "sat3": sat3})
print(ret.text)





