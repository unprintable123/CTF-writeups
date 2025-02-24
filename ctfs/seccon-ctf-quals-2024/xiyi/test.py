import requests
import time
from sage.all import *
from cysignals.alarm import alarm, AlarmInterrupt, cancel_alarm

def get_factor(n):
    url = f"http://factordb.com/api?query={n}"
    r = requests.get(url)
    return r.json()

def try_factor(n):
    print("Trying", n.bit_length(), n)
    if n.is_pseudoprime():
        if n.bit_length() == 518:
            print("Found!", n)
            raise ValueError
        return
    try:
        alarm(20)
        res = ecm.find_factor(n)
    except (AlarmInterrupt, KeyboardInterrupt):
        return
    cancel_alarm()
    print(res)
    if res[0].bit_length() >= 518:
        try_factor(res[0])
    if res[1].bit_length() >= 518:
        try_factor(res[1])

for i in range(8000, 12000):
    if i % 30 != 0:
        continue
    time.sleep(0.2)
    num = abs((-2)**i-1)
    fac_i = ZZ(i).factor()
    for f, d in fac_i:
        o = i//f
        num = num // gcd(num, abs((-2)**o-1)**4)

    print(i, num.bit_length())
    fac = get_factor(num)
    bits = set()
    for f, d in fac["factors"]:
        p = int(f)
        bits.add(p.bit_length())
        if p.bit_length() == 518:
            print("Found!", p)
            break
        if p.bit_length() <= 800 and p.bit_length() >= 518 and fac["status"] != "FF":
            try_factor(ZZ(p))
    print(fac["status"], bits)
    assert 518 not in bits
    
