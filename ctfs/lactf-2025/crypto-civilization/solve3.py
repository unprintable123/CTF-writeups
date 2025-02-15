from pwn import *
import hashlib, os

context.log_level = 'debug'

def xor_bytes(bytes1: bytes, bytes2: bytes) -> bytes:
    if len(bytes1) != len(bytes2):
        raise ValueError("Byte objects must be of the same length")

    return bytes(b1 ^ b2 for b1, b2 in zip(bytes1, bytes2))

def PRG(s: bytes) -> bytes:
    assert len(s) == 2, "You're trying to cheat! Go to Crypto Prison!"
    s_int = int.from_bytes(s, byteorder="big")

    h = hashlib.new("sha3_256")
    h.update(s)

    out = h.digest()

    return out[:4]

prgs = {}

for i in range(2**16):
    s = i.to_bytes(2, 'big')
    prgs[PRG(s)[:]] = s[:]

# io = process(['python3', 'civil.py'])
# nc chall.lac.tf 31173
io = remote('chall.lac.tf', 31173)

for _ in range(200):
    io.recvuntil(b"Here's y: ")
    y = bytes.fromhex(io.recvline().decode().strip())
    print(y)

    for k in prgs.keys():
        xor_ky = xor_bytes(k, y)
        if xor_ky in prgs:
            break


    io.sendline(k.hex())

    cm = io.recvuntil(b"? Show me (hex).").decode()

    if "chicken" in cm:
        io.sendline(prgs[k].hex())
    else:
        if xor_ky in prgs:
            io.sendline(prgs[xor_ky].hex())
        else:
            io.sendline(prgs[k].hex())

io.interactive()