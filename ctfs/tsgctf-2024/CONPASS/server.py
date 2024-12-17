from Crypto.Util.number import getStrongPrime
from fastapi import FastAPI
from pydantic import BaseModel
import math
import time
import json
import string
import os

flag = os.getenv("FLAG", "FAKECTF{THIS_IS_FAKE}")

positions = {
    "user": [3861, -67500, 50947],
    "sat0": [67749, 27294, 94409],
    "sat1": [38630, -52128, -9112],
    "sat2": [-86459, -74172, 8698],
    "sat3": [36173, -84060, 95354],
    "flag": [0,0,0]
}

valid_chars = set(string.printable[:-5])


class AuthData(BaseModel):
    sat0: dict
    sat1: dict
    sat2: dict
    sat3: dict

def distance(a,b):
    dist = 0
    for i in range(3):
        dist += (a[i]-b[i])**2
    return math.sqrt(dist)

def sign(data: str,private_key):
    data_int = int.from_bytes(data.encode(),'little')
    sign = pow(data_int,private_key["d"],private_key["n"]).to_bytes(128,'little').hex()
    return sign

def verify(data: str,signature: str,public_key):
    data_int = int.from_bytes(bytes.fromhex(data),'little')
    sign_int = int.from_bytes(bytes.fromhex(signature),'little')
    return data_int%public_key["n"] == pow(sign_int,public_key["e"],public_key["n"])

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

def my_decoder(hex_data):
    str_data = bytes.fromhex(hex_data).decode('utf-8',errors = 'ignore')
    #trim illegal characters
    str_data = ''.join(filter(lambda x: x in valid_chars, str_data))
    return str_data

app = FastAPI()

keys = []
for i in range(4):
    p = getStrongPrime(512)
    q = getStrongPrime(512)
    n = p*q
    phi = (p-1)*(q-1)
    e = 65537
    d = pow(e,-1,phi)
    pubkey = {"e":e,"n":n}
    prvkey = {"d":d,"n":n}
    keys.append({"public_key":pubkey, "private_key":prvkey})





@app.get("/sat0")
async def sat0():
    
    ut = int(time.time())
    data = {"time": ut-int(distance(positions["sat0"],positions["user"]))}
    data_json = json.dumps(data)
    signature = sign(data_json,keys[0]["private_key"])
    return {"data":data_json.encode().hex(), "sign":signature, "public_key":keys[0]["public_key"]}

@app.get("/sat1")
async def sat1():
    
    ut = int(time.time())
    data = {"time": ut-int(distance(positions["sat1"],positions["user"]))}
    data_json = json.dumps(data)
    signature = sign(data_json,keys[1]["private_key"])
    return {"data":data_json.encode().hex(), "sign":signature, "public_key":keys[1]["public_key"]}

@app.get("/sat2")
async def sat2():
    
    ut = int(time.time())
    data = {"time": ut-int(distance(positions["sat2"],positions["user"]))}
    data_json = json.dumps(data)
    signature = sign(data_json,keys[2]["private_key"])
    return {"data":data_json.encode().hex(), "sign":signature, "public_key":keys[2]["public_key"]}

@app.get("/sat3")
async def sat3():
    
    ut = int(time.time())
    data = {"time": ut-int(distance(positions["sat3"],positions["user"]))}
    data_json = json.dumps(data)
    signature = sign(data_json,keys[3]["private_key"])
    return {"data":data_json.encode().hex(), "sign":signature, "public_key":keys[3]["public_key"]}


@app.post("/auth")
async def auth(auth_data: AuthData):
    try:
        valid = [
            verify(auth_data.sat0["data"],auth_data.sat0["sign"],keys[0]["public_key"]),
            verify(auth_data.sat1["data"],auth_data.sat1["sign"],keys[1]["public_key"]),
            verify(auth_data.sat2["data"],auth_data.sat2["sign"],keys[2]["public_key"]),
            verify(auth_data.sat3["data"],auth_data.sat3["sign"],keys[3]["public_key"])
        ]
    except:
        return {"error": "bad request"}
    if all(valid):
        if is_in_area(auth_data):
            return {"flag": flag}
        else:
            return {"error": "you are not with the flag"}
    else:
        return {"error": "date not properly signed"}