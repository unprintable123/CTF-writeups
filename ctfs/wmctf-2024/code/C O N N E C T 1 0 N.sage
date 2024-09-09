from Crypto.Util.number import *
from os import urandom
import random
# from secret import flag
flag = b"flag{xxxx1xxxxx7xxxxxx5xxxxxx8xxxxx0x}"

def flatter(M):
    from subprocess import check_output
    from re import findall
    z = "[[" + "]\n[".join(" ".join(map(str, row)) for row in M) + "]]"
    ret = check_output(["flatter"], input=z.encode())
    return matrix(M.nrows(), M.ncols(), map(int, findall(b"-?\\d+", ret)))

def padding(flag, length):
    head_length = random.randint(1, length - len(flag))
    tail_length = length - len(flag) - head_length
    while 1:
        re = urandom(head_length) + flag + urandom(tail_length)
        if (bin(bytes_to_long(re)).count("1")) % 2:
            return re


def shuffle(left, right):
    xor_string = [0] * left + [1] * right
    random.shuffle(xor_string)
    xor_string = int("".join(str(i) for i in xor_string), 2)
    return xor_string


l, r = 63, 65
flag = padding(flag, (len(flag) // 4 + 1) * 4)
S = [
    bytes_to_long(
        padding(flag[len(flag) // 4 * i : len(flag) // 4 * (i + 1)], (l + r) // 8)
    )
    for i in range(4)
]
data = [
    [
        [
            shuffle(r, l) ^^ u if j == "1" else shuffle(l, r) ^^ u
            for j in (
                bin(shuffle(r, l) ^^ u)[2:].rjust(l + r, "0")
                if i == "1"
                else bin(shuffle(l, r) ^^ u)[2:].rjust(l + r, "0")
            )
        ]
        for i in bin(u)[2:].rjust(l + r, "0")
    ]
    for u in S
]

def to_bin(s: int):
    return bin(s)[2:].rjust(l + r, '0')

# print(data)


def to_vec(v):
    return vector([int(i) for i in to_bin(v)])

def from_vec(v):
    return int(''.join(str(i) for i in v), 2)

def remove_index(l, i):
    return l[:i]+l[i+1:]

removed_idx = [64]
removed_idx = sorted(removed_idx)

def preprocess(s0, s1):
    for i, idx in enumerate(removed_idx):
        s0 = remove_index(s0, idx-i)
    return s0, s1

def de_preprocess(s0):
    for idx in removed_idx:
        s0 = s0[:idx]+[0]+s0[idx:]
    return s0


def to_eq(xor_value):
    c = to_bin(xor_value)
    s0 = [1 if i == '0' else -1 for i in c]
    s1 = xor_value.bit_count()-64
    # remove 56 64 72
    s0, s1 = preprocess(s0, s1)
    return vector(s0), s1

def solve(target, u=None):
    eqs = []
    for id, i in enumerate(target):
        cnt = 0
        ss0 = vector([0]*(128-len(removed_idx)))
        ss1 = 0
        for j in i:
            s0, s1 = to_eq(j)
            if u is not None:
                assert (to_vec(u)*s0+s1)**2 == 1
            eqs.append((s0, s1))
            ss0 += s0
            ss1 += s1
        

    eqs = sorted(eqs, key=lambda x: abs(x[1]), reverse=True)
    # eqs = eqs[:16384]
    print(len(eqs))

    M = matrix([s0 for s0, s1 in eqs]+[vector([0]*len(eqs[0][0]))])
    M = M.augment(vector([s1 for s0, s1 in eqs]+[256])).T
    M = flatter(M)
    print(M[-1][-100:])
    err = M[-1][:-1]
    if M[-1][-1] < 0:
        err = -err

    if u is not None:
        for (s0, s1), e in zip(eqs, err):
            assert (to_vec(u)*s0+s1) == e
    
    M0 = matrix([s0 for s0, s1 in eqs[:len(err)]])
    target_v = vector([e-s1 for (s0, s1), e in zip(eqs, err)])

    t= M0.solve_right(target_v)
    t = de_preprocess(list(t))
    print(t)
    return t

def check(u, datas):
    for i, t in enumerate(datas):
        j0 = []
        for k in t:
            shu = (k ^^ u)
            assert shu.bit_count() in [63, 65]
            if shu.bit_count() == 63:
                j0.append(1)
            else:
                j0.append(0)
        j0 = from_vec(j0) ^^ u
        assert j0.bit_count() in [63, 65], j0.bit_count()
        assert j0.bit_count() + int(to_bin(u)[i])*2 == 65, f"{j0.bit_count()} {int(to_bin(u)[i])*2}"


import json
with open('output.txt', 'r') as f:
    data = json.load(f)
print(len(data))
recovered_S = []
for i in [0, 1, 2, 3]:
    t = solve(data[i])
    print(long_to_bytes(from_vec(t)))
    check(from_vec(t), data[i])

