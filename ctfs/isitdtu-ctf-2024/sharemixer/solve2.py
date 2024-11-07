from sage.all import *
from pwn import *
from pwnlib.util.iters import mbruteforce
import ast
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes
import time

import hashlib
import sys
import string

def solve_pow(prefix):
    def is_valid(suffix):
        return hashlib.sha256((prefix + suffix).encode()).hexdigest().startswith("000000")

    return mbruteforce(is_valid, length=8, alphabet=string.ascii_letters + string.digits)

context.log_level = "debug"

while True:

    while True:

        # nc 35.187.238.100 5001
        io = remote("35.187.238.100", 5002)
        # io.recvuntil(b"Send a suffix that: \n")
        # chall = io.recvline().strip().decode()
        # prefix = chall.split("sha256(\"")[1].split("\" + ")[0]
        # suffix = str(solve_pow(prefix))
        # io.sendline(suffix.encode())
        # io.recvuntil(b"Suffix:")
        # io = process(["python3", "chall2.py"])

        p = int(io.recvline().split(b" = ")[1])

        if p % 32 != 1:
            io.close()
            continue
        else:
            break


    for g in range(2, 999):
        if pow(g, (p-1)//2, p) == 1:
            continue
        a = pow(g, (p-1)//32, p)
        if a != 1:
            break

    xs = [pow(a, i, p) for i in range(32)]

    io.sendlineafter("Gib me the queries:", " ".join(str(x) for x in xs))

    shares = ast.literal_eval(io.recvline().split(b" = ")[1].strip().decode())

    # print(f"{shares = }")

    io.close()

    s = sum(shares) * pow(32, -1, p) % p
    print(f"{s = }")

    s = long_to_bytes(s)
    
    try:
        print(s.decode())
        break
    except:
        print(s)
        continue


