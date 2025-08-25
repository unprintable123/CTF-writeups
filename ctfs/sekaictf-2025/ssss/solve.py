from sage.all import *
from pwn import *

context.log_level = 'debug'

p = 2 ** 256 - 189
R = PolynomialRing(GF(p), 'x')
t = 29

io = process(["python3", "chall.py"])

def sample():
    io.sendline(str(t).encode())
    while True:
        g = randint(1, p)
        g = pow(g, (p-1)//t, p)
        if g != 1:
            break
    shares = []
    for i in range(t):
        x0 = pow(g, i, p)
        io.sendline(str(x0).encode())
        y0 = int(io.recvline().strip())
        shares.append((x0, y0))
    return R.lagrange_polynomial(shares).coefficients()

s0 = sample()
io.sendline(b'1')
io.recvline()
s1 = sample()

for secret in set(s0) & set(s1):
    io.sendline(str(secret).encode())
    io.interactive()