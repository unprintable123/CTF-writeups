from sage.all import *
from pwn import *
import  random

# io = process(['python3', 'chal.py'])
# nc granular-counter-mode.chal.hitconctf.com 3000
io = remote('granular-counter-mode.chal.hitconctf.com', 3000)


io.recvuntil(b'> ')
io.sendline(b'1')
io.sendline(b'960')
io.recvuntil(b'Here is your certificate for ')
pt = bytes.fromhex(io.recvuntil(b':').decode().strip().strip(":"))
io.recvuntil(b'\n')
ct = bytes.fromhex(io.recvline().decode().strip())

# print(pt.hex())
# print(ct.hex())

nonce = ct[:8]
tag = ct[8:24]
ct = ct[24:]

R = PolynomialRing(GF(2), 'x')
x = R.gen()
F = GF(2**8, name='a', modulus=x**8 + x**4 + x**3 + x**2 + 1)
a = F.gen()
R = PolynomialRing(F, 'x')
x = R.gen()


def from_integer(x: int) -> F:
    coeffs = []
    for i in range(8):
        coeffs.append(x & 1)
        x >>= 1
    assert len(coeffs) == 8
    return F(coeffs[::-1])*a

def to_integer(x: F) -> int:
    coeffs = (x/a).polynomial().coefficients(sparse=False)
    ret = 0
    for i in (range(8)):
        ret = (ret << 1) | int(coeffs[i] if i < len(coeffs) else 0)
    return ret

def granular_mult(a: int, b: int) -> int:
    c = 0
    for i in range(8, -1, -1):
        if (a >> i) & 1:
            c ^= b

        if b & 1:
            b = (b >> 1) ^ 0b10111000
        else:
            b >>= 1

    return c

# for i in range(256):
#     assert to_integer(from_integer(i)) == i, i

# for i in range(256):
#     for j in range(256):
#         assert to_integer(from_integer(i) * from_integer(j)) == granular_mult(i, j), (i, j)

target = b"give me the flag!!!"
target = target.ljust(32, b'\x00')
target_xor = bytes(ti ^ ci for ti, ci in zip(target, pt[:32]))
print(target_xor.hex())

def random_poly(deg):
    u = [x - from_integer(i) for i in range(256)]
    random.shuffle(u)
    poly = prod(u[:deg])
    return poly

good_polys = {}

def check(nonce, tag, ct):
    io.recvuntil(b'> ')
    io.sendline(b'2')
    io.sendline((nonce + tag + ct).hex().encode())
    resp = io.recvline().decode().strip()
    if 'Something went wrong' in resp:
        print(resp)
        return 1
    elif 'This certificate seems to give you nothing...' in resp:
        print(resp)
        return 2
    else:
        print(resp)
        return 0

def test():
    for i in range(16):
        
        while True:
            ct0 = bytearray(ct[:])
            poly = random_poly(57)
            c1 = target_xor[i]
            c2 = target_xor[i + 16]
            p2 = from_integer(c1) * x ** 59 + from_integer(c2) * x ** 58
            p2 -= p2.quo_rem(poly)[1]
            assert p2.quo_rem(poly)[1] == 0
            # print(sum(p2(x=from_integer(j)) == 0 for j in range(256)))
            us = p2.padded_list(60)[::-1]
            # us = poly.padded_list(60)[::-1]
            assert len(us) == 60
            assert us != [0] * len(us), us
            for j, u in enumerate(us):
                ct0[i + 16 * j] ^= to_integer(u)
            res = check(nonce, tag, bytes(ct0))
            if res == 2:
                good_polys[i] = us
                print(f"found {i}")
                break

test()

ct0 = bytearray(ct[:])
for i in range(16):
    us = good_polys[i]
    for j, u in enumerate(us):
        ct0[i + 16 * j] ^= to_integer(u)
print(check(nonce, tag, bytes(ct0)))

io.interactive()
