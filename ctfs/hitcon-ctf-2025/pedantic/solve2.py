from sage.all import *
import hashlib
from math import log2, inf
import random, json
from bisect import bisect_left
from pwn import *
from ast import literal_eval
from tqdm import tqdm
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor

from fastecdsa.curve import secp256k1
from fastecdsa.point import Point

# context.log_level = 'debug'

p = secp256k1.p
q = secp256k1.q
G = secp256k1.G
field_bytes = (p.bit_length() + 7) // 8
scalar_bytes = (q.bit_length() + 7) // 8

def encode_point(pt: Point):
    return pt.x.to_bytes(field_bytes, "big") + pt.y.to_bytes(field_bytes, "big")

def flatter(M):
    from subprocess import check_output
    from re import findall
    z = "[[" + "]\n[".join(" ".join(map(str, row)) for row in M) + "]]"
    ret = check_output(["flatter", "-rhf", "1.005"], input=z.encode())
    return matrix(M.nrows(), M.ncols(), map(int, findall(b"-?\\d+", ret)))

def babai_cvp(B, t, perform_reduction=False):
    if perform_reduction:
        B = B.LLL(delta=0.75)

    G = B.gram_schmidt()[0]
    b = t
    for i in reversed(range(B.nrows())):
        c = ((b * G[i]) / (G[i] * G[i])).round()
        b -= c * B[i]

    return t - b

def decode_point(data: bytes):
    if len(data) != 2 * field_bytes:
        raise ValueError("Invalid point encoding")
    x = int.from_bytes(data[:field_bytes], "big")
    y = int.from_bytes(data[field_bytes:], "big")
    return Point(x, y, secp256k1)

def hash_point(pt: Point):
    h = hashlib.sha256(encode_point(pt)).digest()
    return int.from_bytes(h, "big") % q


def hash_points_to_scalars(pts: list[Point], n: int):
    s = sum([hash_point(pt) for pt in pts]) % q
    ret = []
    for _ in range(n):
        ret.append(s)
        s = (1337 * s + 7331) % q
    return ret

# io = process(['sage', 'server.py'])
# nc pedantic.chal.hitconctf.com 1337
io = remote('pedantic.chal.hitconctf.com', 1337)

io.recvuntil(b"Here is the proof:\n")

def serialize_proof(proof):
    return json.dumps([(encode_point(pt).hex(), z) for pt, z in proof])


def deserialize_proof(s: str):
    return [(decode_point(bytes.fromhex(pt)), z) for pt, z in json.loads(s)]

proof = deserialize_proof(io.recvline().decode().strip())

io.recvuntil(b"proof:")
# io.close()

# print(proof)

proofs = []

cs = hash_points_to_scalars([pt for pt, z in proof], 10)

# pk = G * 12421123

for (pt, z), c in zip(proof, cs):
    # assert G * z == pt + c * pk
    c_inv = pow(c, -1, q)
    z_scaled = (z * c_inv) % q
    pt_scaled = pt * c_inv
    proofs.append((pt_scaled, z_scaled))

target_s = 7331 * pow(-1336, -1, q) % q
assert (1337 * target_s + 7331) % q == target_s

pt0, z0 = proofs[0]
pt0 = pt0 * target_s
z0 = (z0 * target_s) % q
# assert G * z0 == pt0 + target_s * pk

k = 320
items = []
for i in range(k):
    pt = pt0 + G * i
    z = (z0 + i) % q
    # assert G * z == pt + target_s * pk
    items.append((hash_point(pt), pt, z))
t = vector(GF(q), [h for h, pt, z in items])

M = zero_matrix(ZZ, k+2, k+2)
M[0] = vector(ZZ, [target_s]+[8]*k+[100])
M[1:-1, 0] = matrix(ZZ, k, 1, [item[0] for item in items])
M[1:-1, 1:-1] = identity_matrix(ZZ, k)
M[-1, 0] = q
M.rescale_col(0, 2**20)
M = flatter(M)
for v in M.rows():
    if abs(v[-1]) == 100:
        if v[-1] < 0:
            v = -v
        print(v)
        break

v0 = v.list()[1:-1]
v0 = vector(ZZ, [8]*k) - vector(ZZ, v0)
assert v0 * t == target_s

print(v0, min(v0))

fake_proof = []

for count, (h, pt, z) in zip(v0, items):
    for _ in range(count):
        fake_proof.append((pt, z))

def verify(Y, proof):
    Grs, zs = zip(*proof)
    n = len(Grs)
    cs = hash_points_to_scalars(Grs, n)
    return all(G * z == Gr + Y * c for Gr, z, c in zip(Grs, zs, cs)) * n

# print(verify(G * 12421123, fake_proof))
# print(verify(G * 12421123, deserialize_proof(serialize_proof(fake_proof))))

io.sendline(serialize_proof(fake_proof).encode())
io.interactive()
