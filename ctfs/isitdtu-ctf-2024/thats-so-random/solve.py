from sage.all import *
import json
import os
import random
import functools


os.chdir(os.path.dirname(os.path.abspath(__file__)))

class mt19937():
    u, d = 11, 0xFFFFFFFF
    s, b = 7, 0x9D2C5680
    t, c = 15, 0xEFC60000
    l = 18
    n = 624

    def my_int32(self, x):
        return(x & 0xFFFFFFFF)

    def __init__(self, seed):
        w = 32
        r = 31
        f = 1812433253
        self.m = 397
        self.a = 0x9908B0DF
        self.MT = [0] * self.n
        self.index = self.n + 1
        self.lower_mask = (1 << r) - 1
        self.upper_mask = self.my_int32(~self.lower_mask)
        self.MT[0] = self.my_int32(seed)
        for i in range(1, self.n):
            self.MT[i] = self.my_int32((f * (self.MT[i - 1] ^ (self.MT[i - 1] >> (w - 2))) + i))

    def extract_number(self):
        if self.index >= self.n:
            self.twist()
            self.index = 0
        y = self.MT[self.index]
        # this implements the so-called "tempering matrix"
        # this, functionally, should alter the output to
        # provide a better, higher-dimensional distribution
        # of the most significant bits in the numbers extracted
        y = y ^ ((y >> self.u) & self.d)
        y = y ^ ((y << self.s) & self.b)
        y = y ^ ((y << self.t) & self.c)
        y = y ^ (y >> self.l)
        self.index += 1
        return self.my_int32(y)

    def twist(self):
        for i in range(0, self.n):
            x = (self.MT[i] & self.upper_mask) + (self.MT[(i + 1) % self.n] & self.lower_mask)
            xA = x >> 1
            if(x % 2) != 0:
                xA = xA ^ self.a
            self.MT[i] = self.MT[(i + self.m) % self.n] ^ xA



rng = mt19937(0x17133709)
data = [rng.extract_number()>>3 for _ in range(0x13337)]


# with open("output.txt") as f:
#     data = json.load(f)

nbits = int(0x13371337*1.337).bit_length()
acc = int(0x13371337*1.337) / 2**nbits

def int_to_bits(x):
    return [(x >> (31-i)) & 1 for i in range(32)]

def bits_to_int(y):
    y = y[:]
    for i in range(32):
        if y[i] is None:
            y[i] = random.randint(0, 1)
    return sum([y[i] << (31-i) for i in range(32)])

def temper(t):
    y = t ^ (t >> 11)
    y = y ^ ((y << 7) & 0x9d2c5680)
    y = y ^ ((y << 15) & 0xefc60000)
    y = y ^ (y >> 18)
    return y

m = []
for i in range(32):
    c = temper(1<<(31-i))
    m.append(int_to_bits(c))
M = matrix(GF(2), m).transpose()
M_inv = M.inverse()

R = PolynomialRing(GF(2), [f"x_{i}_{j}" for j in range(3) for i in range(3)])

xlist = R.gens()
xlist = [list(xlist[3*i:3*(i+1)]) for i in range(3)]

states = []
for t in data:
    l = []
    for i in range(nbits):
        l.append((t >> i) & 1)
    l = l[::-1]
    states.append(l)

@functools.lru_cache(maxsize=8192)
def make_eq(idx, vars_id):
    l = states[idx] + xlist[vars_id]
    l = vector(R, l)
    return M_inv * l

def solve_eqs(eqs):
    G = Sequence(eqs)
    
    A, v = G.coefficients_monomials(sparse = True)

    if v[-1] != 1:
        return True

    v0 = -A[:, -1]
    A = A[:, :-1]
    try:
        s = A.solve_right(v0)
    except ValueError:
        return False
    return True

magA = vector(int_to_bits(0x9908b0df))

@functools.lru_cache(maxsize=4096)
def check_pair(id1, id2, id3):
    # s1: k-(n-1), s2: k-(n-m), s3: k
    s1 = make_eq(id1, 0)
    s2 = make_eq(id2, 1)
    s3 = make_eq(id3, 2)
    s1_new = [None] + list(s1[:-1])
    s1_new[1] = None

    def is_match(a, b):
        return a[16] == b[16]

    c = s2 + s3
    if not is_match(s1_new, c):
        c = magA + c
    
    u = []
    for i in range(32):
        if s1_new[i] is None:
            continue
        else:
            if c[i].degree() <= 0 and s1_new[i].degree() <= 0:
                if c[i] != s1_new[i]:
                    return False
                else:
                    continue
            u.append(s1_new[i] - c[i])

    return solve_eqs(u)

# dist1 = int(397 * acc) - 3
# dist2 = int(624 * acc) - 1
dist1 = 396
dist2 = 623

difficulty = 6

for idx in range(len(data) - 700):
    find = True
    for j in range(difficulty):
        if not check_pair(idx+j, idx+j+dist1, idx+j+dist2):
            find = False
            break
    if find:
        print(idx)
        break

assert idx < len(data) - 10000

idx = 0

order_list = [(a, b, c) for a in range(1, 20) for b in range(1, 20) for c in range(1, 20)]
order_list = sorted(order_list, key = lambda x: x[0] + x[1] + x[2])

def get_next_pair(idx1, idx2, idx3):
    for offset1, offset2, offset3 in order_list:
        if check_pair(idx1+offset1, idx2+offset2, idx3+offset3):
            return idx1+offset1, idx2+offset2, idx3+offset3
    raise ValueError("Not found")

idx1 = idx
idx2 = idx + dist1
idx3 = idx + dist2

pairing = []

while idx3 < len(data) - 50:
    pairing.append([idx1, idx2, idx3])
    idx1, idx2, idx3 = get_next_pair(idx1, idx2, idx3)
    print(idx1, idx2, idx3)

with open("pairing.txt", "w") as f:
    f.write(json.dumps(pairing))


