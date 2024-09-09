from pwn import *
from pwnlib.util.iters import mbruteforce
import hashlib
import string
import json, random
from myenigma import myReflector, myrotors

hashed = bytes.fromhex("79ad2e06ca812cf6f3352147ca6c3c9a99ae66a1a2f48c0ede42a7db4177eec7")
suffix = "hJK3T6zpsRhNbjtC"

def is_pow(s):
    return hashlib.sha256((s+suffix).encode()).digest() == hashed

def get_samples(return_io=False):
    global hashed, suffix
    io = remote("127.0.0.1", 8840)
    # io = remote("8.147.133.38", 31665)
    io.recvuntil(b"[+] sha256(XXXX+")
    suffix = (io.recvuntil(b") == ").strip()[:-4]).decode()
    hashed = bytes.fromhex(io.recvuntil(b"\n").strip().decode())
    pow = mbruteforce(is_pow, string.ascii_letters+string.digits, 4)
    io.sendline(pow.encode())
    io.recvuntil(b"XXXX: ")
    c = []
    for _ in range(11):
        c.append(io.recvline().strip().decode().upper())
    if return_io:
        return c, io
    io.close()
    return c

def to_set(slist):
    c = [set('ABCDEFGHIJKLMNOPQRSTUVWXYZ') for _ in range(47)]
    for s in slist:
        for i in range(47):
            c[i].discard(s[i])
    return c



k = 4
n = 48
# sample_list = [get_samples() for _ in range(n)]
# with open("samples.json", "w") as f:
#     json.dump(sample_list, f)
with open("samples.json", "r") as f:
    sample_list = json.load(f)
possible_charsets = [to_set(s) for s in sample_list]

brute_charset = [chr(0x61+i) for i in range(30)]

def recursive_brute_force(p_charsets, ind):
    if ind == n:
        print(p_charsets)
        return True
    target_s = possible_charsets[ind]
    for i in range(30):
        new_charsets = []
        for j in range(17):
            u = p_charsets[j].intersection(target_s[i+j])
            if len(u) == 0:
                break
            new_charsets.append(u)
        if len(new_charsets) == 17:
            if recursive_brute_force(new_charsets, ind+1):
                print(i)
                return True
    return False

def check_intersection(order):
    if len(order) != k:
        return False
    pc = [possible_charsets[i][ord(order[i])-0x61:ord(order[i])-0x61+17] for i in range(k)]
    # print([ord(order[i])-0x61 for i in range(k)])
    p_charsets = []
    for tl in zip(*pc):
        u = set.intersection(*tl)
        if len(u) == 0:
            return False
        p_charsets.append(u)
    # print(p_charsets)
    return recursive_brute_force(p_charsets, k)

key = "THEWEATHERTODAYIS"
# pcs = [set("X") for i in range(17)]
# print(recursive_brute_force(pcs, 0))
# print(check_intersection("jj{an"))
# print(check_intersection("}cv~"))
# order = mbruteforce(check_intersection, brute_charset, k)
# print(order)

# samples, io = get_samples(True)
# chars = to_set(samples)

dayrotors = tuple(random.sample(myrotors, 3))
print(myrotors[0].encipher_left(myrotors[0].encipher_right("A")))
