from pwn import *
from Crypto.Util.number import bytes_to_long, long_to_bytes
import os

context.log_level = 'debug'

# io = process(['sage', 'chall.py'])
# nc 34.170.146.252 50953
io = remote('34.170.146.252', 50953)

def check(x):
    io.recvuntil(b'Guess the flag in integer:')
    io.sendline(str(x).encode())
    ret = io.recvline().strip().decode()
    if 'Weird' in ret:
        return False
    return True

def pad(s):
    return b'\x7f' + s + b'\x7f' * (30 - len(s))

prefix = b''

for _ in range(30):
    for i in range(128):
        b = bytes([i])
        if check(bytes_to_long(pad(prefix + b))):
            prefix += b
            print(f"Found byte: {b} -> {prefix}")
            break

print(prefix)

