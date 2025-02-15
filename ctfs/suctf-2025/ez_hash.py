from Crypto.Util.number import *
from sage.all import *
from pwn import *
import random
import string
import itertools
import hashlib


flag = b'SUCTF{??????????????????????????????}'

class myhash:
    def __init__(self,n):
        self.g = 91289086035117540959154051117940771730039965839291520308840839624996039016929
        self.n = n

    def update(self,msg: bytes):
        for i in range(len(msg)):
            self.n = self.g * (2 * self.n + msg[i])
            self.n = self.n & ((1 << 383) - 1)

    def digest(self) -> bytes:
        return ((self.n - 0xd1ef3ad53f187cc5488d19045) % (1 << 128)).to_bytes(16,"big")

def xor(x, y):
    x = b'\x00'*(16-len(x)) + x
    y = b'\x00'*(16-len(y)) + y
    return long_to_bytes(bytes_to_long(bytes([a ^ b for a, b in zip(x, y)])))

def fn(msg: bytes):
    n0 = getRandomNBitInteger(382)
    h = myhash(n0)
    ret = bytes([0] * 16)
    for b in msg:
        h.update(bytes([b]))
        ret = xor(ret,h.digest())
    return ret

# your_input = bytes.fromhex(input("give me your msg ->").strip())
# if fn(your_input) == b'justjusthashhash':
#     print(flag)
# else:
#     print("try again?")

alph = string.ascii_letters + string.digits

io = remote("1.95.46.185", 10007)
io.recvuntil(b'XXXX+')
suf = io.recvuntil(b')')[:-1]
targ = bytes.fromhex(io.recvline().split()[-1].decode())


def solve_pow(suf, targ):
    for x in itertools.product(alph, repeat=4):
        x = ''.join(x)
        if hashlib.sha256(x.encode() + suf).digest() == targ:
            return x.encode()
    else:
        import sys
        print("Failed")
        sys.exit(1)

io.sendline(solve_pow(suf, targ))
n0 = int(io.recvline_contains(b'n0 = ').split()[-1])
print(f"n0 = {n0}")

h = myhash(n0)

msg = b"\x00" * 388

ret = bytes([0] * 16)
for b in msg:
    h.update(bytes([b]))
    ret = xor(ret,h.digest())

target = xor(ret, b"justjusthashhash")


chunks = []
M = []

def get_hash(msg):
    h = myhash(0)
    ret = bytes([0] * 16)
    for b in msg:
        h.update(bytes([b]))
        ret = xor(ret,h.digest())
    return ret

def to_vec(h):
    vec = []
    for i in range(128):
        if h & (1 << i):
            vec.append(1)
        else:
            vec.append(0)
    return vec

for _ in range(150):
    msg = random.randbytes(16) + b"\x00"*388
    h = bytes_to_long(get_hash(msg))
    chunks.append(msg)
    M.append(to_vec(h))

M = matrix(GF(2), M)
target_v = vector(GF(2), to_vec(bytes_to_long(target)))

c = M.solve_left(target_v)

msg = b"\x00" * 388
for i in range(150):
    if c[i] == 1:
        msg += chunks[i]


io.sendline(msg.hex())

h = myhash(n0)
ret = bytes([0] * 16)

for b in msg:
    h.update(bytes([b]))
    ret = xor(ret,h.digest())
print(ret)

io.interactive()


