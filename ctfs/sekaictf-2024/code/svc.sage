from pwn import *
from Crypto.Util.number import bytes_to_long, getPrime
import sys
sys.setrecursionlimit(10**6)

def flatter(M):
    from subprocess import check_output
    from re import findall
    z = "[[" + "]\n[".join(" ".join(map(str, row)) for row in M) + "]]"
    ret = check_output(["flatter"], input=z.encode())
    return matrix(M.nrows(), M.ncols(), map(int, findall(b"-?\\d+", ret)))

def solve(N, m0, m1, x0, x1):
    R.<c> = PolynomialRing(Zmod(N))
    poly = c**2 - m0

    r1 = m1 - c**3

    def poly_pow(r, n, mod):
        if n == 0:
            return R(1)
        if n == 1:
            return r
        if n % 2 == 0:
            u = poly_pow(r, n // 2, mod)
            u = u * u
            _, u = u.quo_rem(mod)
            return u
        else:
            t = poly_pow(r, (n - 1)//2, mod)
            t = (t**2) * r
            _, t = t.quo_rem(mod)
            return t

    r2 = poly_pow(r1, N, poly)-(x0-x1)
    # print(r2)
    e, f = r2.coefficients()
    y = -e/f
    p = ZZ(gcd(N, poly(c=y)))


    assert N % p == 0 and p != 1
    qr = N // p

    mp0 = m0 - p**2
    mp1 = m1 - p**3

    poly2 = c**2 - mp0
    r1 = mp1 - c**3

    r2 = poly_pow(r1, N, poly2)-(x0-x1)
    e, f = r2.coefficients()
    y = ZZ(-e/f)
    assert poly2(c=y) == 0
    return qr, y

def get_lower_bound(s: bytes):
    return bytes_to_long(s+"\x00"*(128-len(s)))

def sample():
    io = process(["python3", "chall.py"])
    # io = remote("squares-vs-cubes.chals.sekai.team", 1337, ssl=True)
    N = int(io.recvline().strip().split(b" = ")[1])
    x0 = int(io.recvline().strip().split(b" = ")[1])
    x1 = int(io.recvline().strip().split(b" = ")[1])
    io.recvuntil(b"Send me v: ")
    io.sendline(str(x0).encode())
    m0 = int(io.recvline().strip().split(b" = ")[1])
    m1 = int(io.recvline().strip().split(b" = ")[1])
    io.close()
    return solve(N, m0, m1, x0, x1)



qr, y = sample()
q_approx = qr * get_lower_bound(b"SEKAI{") // y





