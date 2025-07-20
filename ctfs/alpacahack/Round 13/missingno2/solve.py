from sage.all import *
from pwn import *
from ast import literal_eval
import os
from utils import element_to_int, int_to_element
from tqdm import tqdm

ps = [(2, 255), (3, 161), (5, 110), (7, 91), (11, 74), (13, 69)]
for p, j in ps:
    assert (p**j).bit_length() == 256, f"Failed for {p}^{j}"

possible_flags = [list(range(128)) for _ in range(52)]

def sample(p, k):
    order = p**k
    F = GF(order, name="z", modulus=pari.minpoly(pari.ffgen(order)))
    # io = process(['sage', 'chall.sage'])
    # nc 34.170.146.252 28596
    io = remote('34.170.146.252', 28596)

    io.sendlineafter(b"Missing order: ", hex(order).encode())

    A = literal_eval(io.recvline().decode().strip())
    b = literal_eval(io.recvline().decode().strip())
    A = matrix(F, [[int_to_element(x, F) for x in row] for row in A])
    b = vector(F, [int_to_element(x, F) for x in b])
    pad = literal_eval(io.recvline().decode().strip())
    io.close()

    M = matrix(F, 52, 52)
    M[1] = b
    M[2:] = A.transpose()

    v0 = []
    for j in tqdm(range(52)):
        ind = list(range(52))
        ind.remove(j)
        MM = M[1:, ind]
        v0.append((-1)**j * MM.det())
    v0 = vector(F, v0)

    V = matrix(GF(p), [v.list() for v in v0])
    assert len(V.left_kernel().basis()) == 1
    t = V.left_kernel().basis()[0]

    cc = b"Alpaca"
    cc = [a^b for a, b in zip(cc, pad)]
    cc = [c % p for c in cc]
    for ind in range(6):
        if cc[ind] != 0:
            t = t * cc[ind] / t[ind]
            break
    print(t)
    for ind in range(52):
        new_possible_flag0 = []
        p0 = pad[ind]
        r0 = t[ind]
        for f0 in possible_flags[ind]:
            if (f0 ^ p0) % p == r0:
                new_possible_flag0.append(f0)
        possible_flags[ind] = new_possible_flag0

sample(11, 74)
print(possible_flags)

sample(13, 69)
print(possible_flags)

sample(7, 91)
print(possible_flags)
