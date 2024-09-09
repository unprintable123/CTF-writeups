from falcon import falcon
from falcon.encoding import compress, decompress
from falcon.ntt import mul_zq
from flag import flag
import json
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

sk = falcon.SecretKey(64)
pk = falcon.PublicKey(sk)

io = remote("hayabusa.chals.sekai.team", 1337, ssl=True)

io.recvuntil(b"h = ")
h = json.loads(io.recvline().strip().decode())
pk.h = h
sk.h = h

print(h)

q = 12 * 1024 + 1

def one_hot(i):
    ret = [0]*64
    ret[i] = 1
    return ret

B0 = matrix([mul_zq(one_hot(i), h) for i in range(64)])
B = block_matrix(ZZ, [[identity_matrix(64), -B0], [zero_matrix(64), identity_matrix(64)*q]])
B = flatter(B)

while 1:
    salt = b"\x61" * 40

    hashed = sk.hash_to_point(b"Can you break me", salt)

    v_h = vector([0]*64+hashed)

    re = v_h - babai_cvp(B, v_h, perform_reduction=False)
    print("cvp:", re)

    v0 = vector(GF(q), re[:64])

    print(list(re[:64]))

    print(mul_zq(list(re[:64]), h))
    print(hashed)

    fake_sig = b"\x36" + salt + compress(list(re[:64]), 122-41)

    if pk.verify(b"Can you break me", fake_sig):
        print("well done!!")
        break

io.sendline(fake_sig.hex())
io.interactive()


