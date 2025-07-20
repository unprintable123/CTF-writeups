from sage.all import *
from pwn import *
from ast import literal_eval
import os
from utils import element_to_int, int_to_element

order = 0xdead1337cec2a21ad8d01f0ddabce77f57568d649495236d18df76b5037444b1
F = GF(order, name="z", modulus=pari.minpoly(pari.ffgen(order)))


def sample():
    # io = process(['sage', 'chall.sage'])
    # nc 34.170.146.252 23640
    io = remote('34.170.146.252', 23640)

    A = literal_eval(io.recvline().decode().strip())
    b = literal_eval(io.recvline().decode().strip())
    A = matrix(F, [[int_to_element(x, F) for x in row] for row in A])
    b = vector(F, [int_to_element(x, F) for x in b])
    io.close()

    M = matrix(F, 52, 52)
    M[1] = b
    M[2:] = A.transpose()
    M2 = M.adjugate()
    v0 = M2.transpose()[0]

    return [v.list() for v in v0]

data = []
for _ in range(10):
    u = sample()
    # transpose
    u = [[u[j][i] for j in range(len(u))] for i in range(len(u[0]))]
    data.extend(u)

V = matrix(GF(6821063305943), data)
print(V.rank())
b = V.right_kernel().basis()[0]
print(b*ord("A")/b[0])



