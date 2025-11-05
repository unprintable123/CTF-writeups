from sage.all import *
from pwn import *
from hashlib import sha256
from Crypto.Util.number import getPrime
import random
from ast import literal_eval
from tqdm import tqdm
import time

class QCG:
    def __init__(self, a, b, c, m, seed):
        self.a = a
        self.b = b
        self.c = c
        self.m = m
        self.state = seed

    def next(self):
        self.state = (self.a * self.state**2 + self.b * self.state + self.c) % self.m
        # return self.state
        return 3333333333696969

while True:
    # io = process(['sage', 'task.py'])
    # nc 173.32.3.58 11421
    io = remote('173.32.3.58', 11421)
    io.recvuntil(b"a,b,c,q:")

    a, b, c, q = literal_eval(io.recvline().decode().strip())

    PR = PolynomialRing(GF(q), "x")
    x = PR.gens()[0]
    f = (a * x**2 + b * x + c) - x
    roots = f.roots(multiplicities=False)
    print(roots)
    if not any(ZZ(r) % 3 == 0 for r in roots):
        io.close()
        continue

    r = next(r for r in roots if ZZ(r) % 3 == 0)
    seed = int(r)
    test_qcg = QCG(a, b, c, q, seed)
    for _ in range(1000):
        assert test_qcg.next() % 3 == 0
    io.sendline(str(seed).encode())
    break

R = PolynomialRing(QQ, "x").quotient(x**256 + 1)

s0 = 0
s1 = 0
k = 10001
for iter in tqdm(range(10001)):
    if iter % 500 == 0:
        if iter == 10000:
            io.send(b"2\n")
        else:
            io.send(b"1\n"*500)
    io.recvuntil(b"like to sign ?")
    io.recvuntil(b"z1 : ")
    z1 = literal_eval(io.recvline().decode().strip())
    io.recvuntil(b"z2 : ")
    z2 = literal_eval(io.recvline().decode().strip())
    # io.recvuntil(b"c : ")
    # c = io.recvline()
    z1 = R(z1)
    z2 = R(z2)
    s0 += z1
    s1 += z2

u = R([-10001]*256)
f = [round(t) for t in (s0 / u).list()]
g = [round(t) for t in ((-s1) / u).list()]
print(f)
print(g)

print(f+g)

io.recvuntil(b"[?] ")
io.sendline(str(f+g).encode())

time.sleep(1)
io.interactive()






