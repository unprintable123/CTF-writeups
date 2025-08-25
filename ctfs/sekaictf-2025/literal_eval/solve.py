from math import floor, ceil, log2
from Crypto.Util.number import bytes_to_long
import os
from hashlib import shake_128
from ast import literal_eval
from secrets import token_bytes
from pwn import *

class WOTS:
    def __init__(self, m: int = 256, w: int = 21):
        assert m % 8 == 0
        self.n = 128
        self.m = m
        self.w = w
        self.l1 = ceil(m / log2(w))
        self.l2 = floor(log2(self.l1*(w-1)) / log2(w)) + 1
        self.l = self.l1 + self.l2 # 62 by default

        self.sk = [token_bytes(self.n // 8) for _ in range(self.l)]
        self.pk = [WOTS.chain(sk, self.w - 1) for sk in self.sk]
    
    def sign(self, digest: bytes) -> list[bytes]:
        assert len(digest) == self.m // 8
        d1 = WOTS.pack(bytes_to_long(digest), self.l1, self.w)
        checksum = sum(self.w-1-i for i in d1)
        d2 = WOTS.pack(checksum, self.l2, self.w)
        d = d1 + d2

        sig = [WOTS.chain(self.sk[i], self.w - d[i] - 1) for i in range(self.l)]
        return sig

    def get_pubkey_hash(self) -> bytes:
        hasher = shake_128(b"\x04")
        for i in range(self.l):
            hasher.update(self.pk[i])
        return hasher.digest(16)

    @staticmethod
    def pack(num: int, length: int, base: int) -> list[int]:
        packed = []
        while num > 0:
            packed.append(num % base)
            num //= base
        if len(packed) < length:
            packed += [0] * (length - len(packed))
        return packed
    
    @staticmethod
    def chain(x: bytes, n: int) -> bytes:
        if n == 0:
            return x
        x = shake_128(b"\x03" + x).digest(16)
        return WOTS.chain(x, n - 1)

    @staticmethod
    def verify(digest: bytes, sig: list[bytes], m: int = 256, w: int = 21) -> bytes:
        l1 = ceil(m / log2(w))
        l2 = floor(log2(l1*(w-1)) / log2(w)) + 1
        l = l1 + l2
        d1 = WOTS.pack(bytes_to_long(digest), l1, w)
        checksum = sum(w-1-i for i in d1)
        d2 = WOTS.pack(checksum, l2, w)
        d = d1 + d2

        sig_pk = [WOTS.chain(sig[i], d[i]) for i in range(l)]
        hasher = shake_128(b"\x04")
        for i in range(len(sig_pk)):
            hasher.update(sig_pk[i])
        sig_hash = hasher.digest(16)
        return sig_hash

def get_d(digest, m = 256, w = 21):
    l1 = ceil(m / log2(w))
    l2 = floor(log2(l1*(w-1)) / log2(w)) + 1
    l = l1 + l2
    d1 = WOTS.pack(bytes_to_long(digest), l1, w)
    checksum = sum(w-1-i for i in d1)
    d2 = WOTS.pack(checksum, l2, w)
    d = d1 + d2
    return d

# io = process(["python3", "server.py"])
io = remote("literal-eval.chals.sekai.team", 1337, ssl=True)
io.recvuntil(b"public key:")
root = bytes.fromhex(io.recvline().strip().decode())
k = 255

def send(msg):
    io.recvuntil(b"input:")
    io.sendline(str(msg).encode())
    ret = io.recvline().decode()
    print(len(ret))
    if "Traceback" in ret:
        io.interactive()
    return literal_eval(ret)

msgs = [os.urandom(32) for _ in range(k)]
disgests = [shake_128(b"\x00" + msg).digest(32) for msg in msgs]
ds = [get_d(digest) for digest in disgests]
# sigs = challenge.sign(k, {i: 0 for i in range(k)}, msgs)
sigs = send({
    "type": "sign",
    "num_sign": k,
    "inds": {i: 0 for i in range(k)},
    "messages": msgs,
})

target_digest = shake_128(b"\x00" + b"Give me the flag").digest(32)
target = get_d(target_digest)

def test():
    best_log_prob = 999.0
    for _ in range(2**24):
        digest = os.urandom(32)
        ds = get_d(digest)
        log_prob_new = 0.0
        for d, t in zip(ds, target):
            if d > t:
                log_prob_new -= log2((1+t)/21)
        best_log_prob = min(best_log_prob, log_prob_new)
    print(f"Best log probability: {best_log_prob}")
# test()

wots_sign = []
for i in range(len(target)):
    find = False
    for dd, sig in zip(ds, sigs):
        if dd[i] == target[i]:
            wots_sign.append(sig[0][i])
            find = True
            break
    assert find

forged_sig = [wots_sign] + sigs[0][1:]
print(send({
    "type": "get_flag",
    "sig": [forged_sig],
}))

