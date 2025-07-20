from py_ecc import bn128 # pip install py-ecc
from sage.all import *
from pwn import process, remote
from random import randrange

F2 = GF(bn128.FQ.field_modulus**2, 'w', modulus=[1, 0, 1])
w = F2.gen()

b2 = eval(str(bn128.b2))
b2 = F2([b2[0], b2[1]])

E = EllipticCurve(F2, [0, b2])
C = E.random_point()

A = bn128.multiply(bn128.G1, randrange(bn128.curve_order))
B = bn128.multiply(bn128.G1, randrange(bn128.curve_order))
C = tuple([bn128.FQ2([int(x) for x in C.x().list()]), bn128.FQ2([int(y) for y in C.y().list()])])

io = remote("34.170.146.252", 7648)

io.sendlineafter(b"Input G1: ", str(A).encode())
io.sendlineafter(b"Input G1: ", str(B).encode())
io.sendlineafter(b"Input G2: ", str(C).encode())

io.interactive()
