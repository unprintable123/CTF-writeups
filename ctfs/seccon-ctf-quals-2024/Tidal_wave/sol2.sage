import os
from real_output import *
import secrets, hashlib
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

os.chdir(os.path.dirname(__file__))

def flatter(M):
    from subprocess import check_output
    from re import findall
    z = "[[" + "]\n[".join(" ".join(map(str, row)) for row in M) + "]]"
    ret = check_output(["flatter"], input=z.encode())
    return matrix(M.nrows(), M.ncols(), map(int, findall(b"-?\\d+", ret)))

def get_Rrandom(R):
    return secrets.randbelow(int(R.order()))

def make_G(R, alphas):
    mat = []
    for i in range(k):
        row = []
        for j in range(n):
            row.append(alphas[j]^i)
        mat.append(row)
    mat = matrix(R, mat)
    return mat

n, k = 36, 8
prime_bit_length = 512
R = Zmod(N)

G = make_G(R, alphas)

key_v = vector(R, key_encoded)

G_ext = G.transpose().augment(key_v)

while True:
    subset = random.sample(range(n), 9)
    d = (G_ext[subset]).det()
    if gcd(d, N) > 1:
        print(gcd(d, N), subset)
        break

p = ZZ(gcd(d, N))
assert N % p == 0
q = N // p

Gp = G.change_ring(Zmod(p))
Gq = G.change_ring(Zmod(q))

while True:
    subset = random.sample(range(n), 9)
    d = (G_ext[subset]).det()
    if gcd(d, N) == p:
        G0 = Gp[:, subset]
        target = vector(Zmod(p), G_ext[subset].transpose()[-1])
        u1 = G0.solve_left(target)
        break

while True:
    subset = random.sample(range(n), 9)
    d = (G_ext[subset]).det()
    if gcd(d, N) == q:
        G0 = Gq[:, subset]
        target = vector(Zmod(q), G_ext[subset].transpose()[-1])
        u2 = G0.solve_left(target)
        break

rec_key = []
for a, b in zip(u1, u2):
    rec_key.append(crt([ZZ(a), ZZ(b)], [p, q]))

print(rec_key)
rec_key = vector(R, rec_key)

key = hashlib.sha256(str(rec_key).encode()).digest()
cipher = AES.new(key, AES.MODE_ECB)
print(cipher.decrypt(encrypted_flag))

# M = block_matrix(ZZ, [[identity_matrix(ZZ, k)*(2**1000-64), G], [zero_matrix(ZZ, n, k), identity_matrix(ZZ, n)*N]])

# v = vector(R, list(p_encoded))

# M_embed = block_matrix(ZZ, [[2**1000, matrix(ZZ, [2**999]*k+list(p_encoded))], [zero_matrix(ZZ, n+k, 1), M]])

# M_embed = flatter(M_embed)
# M_embed = M_embed.LLL()
# v = M_embed[1]
# v = v + vector(ZZ, [0] + [2**999]*k + [0]*n)

# print(v)
