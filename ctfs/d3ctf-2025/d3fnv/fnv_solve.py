from sage.all import *
from pwn import *

def flatter(M):
    from subprocess import check_output
    from re import findall
    z = "[[" + "]\n[".join(" ".join(map(str, row)) for row in M) + "]]"
    ret = check_output(["flatter"], input=z.encode())
    return matrix(M.nrows(), M.ncols(), map(int, findall(b"-?\\d+", ret)))

def babai_cvp(B, t, perform_reduction=True):
    if perform_reduction:
        B = B.LLL(delta=0.75)

    G = B.gram_schmidt()[0]
    b = t
    for i in reversed(range(B.nrows())):
        c = ((b * G[i]) / (G[i] * G[i])).round()
        b -= c * B[i]

    return t - b
# 35.241.98.126:31884
io = remote("35.241.98.126", 31884)
io.send(b"G")
io.recvuntil(b"p = ")
p = int(io.recvline().strip())
print(f"p = {p}")

k = 64
random_token_hashes = []
for _ in range(k):
    io.send(b"H")
    io.recvuntil(b"Token Hash: ")
    random_token_hash = int(io.recvline().strip())
    random_token_hash = (random_token_hash ^ 32)
    random_token_hashes.append(random_token_hash)

# io.send(b"S")
# io.recvuntil(b"key = ")
# key = int(io.recvline().strip())
# print(f"key = {key}")

M = block_matrix(ZZ, [[p, matrix(ZZ, [random_token_hashes])*2**20], [0, identity_matrix(k)]])
M = M.transpose()
M = flatter(M)

T = M[:31, 1:].right_kernel().matrix()
T = flatter(T)
v0 = T[0]
v0 = babai_cvp(T, vector(ZZ, [88]*k), perform_reduction=False)

T[0] = v0
T = T.change_ring(GF(p))
t = T.solve_right(vector(GF(p), [1] + [0] * 32))
t = vector(ZZ, t)

# K = T.right_kernel().matrix()
# K = K.change_ring(ZZ)
# K = block_matrix(ZZ, [[K], [identity_matrix(k)*p]])
# K = K.LLL()
# K = K[32:]


# b = babai_cvp(K, t, perform_reduction=False)
# t = t - b
# print(t)

r = 0
for i in range(64):
    r += t[i] * random_token_hashes[i]
    r %= p
print(f"r = {r}")


# M2 = block_matrix(ZZ, [[p, matrix(ZZ, [pow(key, i+1, p) for i in range(32)])], [0, identity_matrix(32)]])
# M2 = M2.transpose()
# M2 = flatter(M2)

# rv = vector(ZZ, [r]+[0]*32)
# print(rv - babai_cvp(M2,rv , perform_reduction=False))

R = PolynomialRing(GF(p), 'x')
x = R.gen()
f = 128 * x ** 32 + x ** 31 - r
roots = f.roots()
if len(roots) == 0:
    print("No roots found")
else:
    print(roots)
    guess_key = roots[0][0]

io.send(b"F")
io.recvuntil(b"Here is a random token x: ")
x = io.recvline().strip().decode()
print(f"x = {x}")

def H4sh(value:str, p, key):
    length = len(value)
    x = int(ord(value[0]) << 7) % int(p)
    for c in value:
        x = int((key * x) % p) ^ ord(c)
    
    x ^= length
    
    return x

hash_value = H4sh(x, p, guess_key)
io.send(f"{hash_value}\n".encode())
io.interactive()

