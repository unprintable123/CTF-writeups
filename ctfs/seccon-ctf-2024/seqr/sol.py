from sage.all import *
import hashlib

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from ecdsa import SigningKey, SECP256k1
from gmpy2 import legendre

fake_p = prod(prime_range(3, 196))

# l = [None] * 256
# for i in range(256):
#     if i%3==2 or i %5==0 or i % 7==1:
#         l[i] = 1
#     else:
#         l[i] = 0

# # 1 0 2
# # 0 1 2
# # 2 0 1

# print("".join(map(str, l)))


class PRNG:
    """Legendre PRF is believed to be secure
    ex. https://link.springer.com/chapter/10.1007/0-387-34799-2_13
    """

    def __init__(self, initial_state: int, p: int) -> None:
        self._state = initial_state
        self.p = p

    def __call__(self, n_bit: int) -> int:
        out = 0
        for _ in range(n_bit):
            out <<= 1
            tmp = legendre(self._state, self.p)
            out |= (1 + tmp) // 2 if tmp != 0 else 1
            self._state += 1
            self._state %= self.p
        return out

p = 2**256-2**32-2**9 -2**8 - 2**7 - 2**6 - 2**4 - 1
Fp = GF(p)

E = EllipticCurve(Fp, [0, 7])
G = E((55066263022277343669578718895168534326250603453777594175500187360389116729240, 
32670510020758816978083085130507043184471273380659243275938904335757337482424))
n  = 115792089237316195423570985008687907852837564279074904382605163141518161494337
Fn = GF(n)

d = randint(1, n - 1)
a=  randint(1, fake_p)
print(a, d, (-a) * pow(256, -1, 105) % 105)
prng = PRNG(a, fake_p)


def hashit(msg):	
	return Integer('0x' + hashlib.sha256(msg.encode()).hexdigest())

def flatter(M):
    from subprocess import check_output
    from re import findall
    z = "[[" + "]\n[".join(" ".join(map(str, row)) for row in M) + "]]"
    ret = check_output(["flatter"], input=z.encode())
    return matrix(M.nrows(), M.ncols(), map(int, findall(b"-?\\d+", ret)))



def ecdsa_sign(d, e):
    r = 0 
    s = 0
    while s == 0:
        k = 1
        while r == 0:
            k = prng(256)
            Q = k * G
            x1, y1 = Q.xy()
            r = Fn(x1)
        
        s = Fn(k) ** (-1) * (e + d * r) 
    return r, s, k

e = 523292266480032572263097387253846278739400489039
# raw_sign = [ecdsa_sign(d, e) for _ in range(3333)]
raw_sign = []

with open("output.txt", "r") as f:
    enc = f.readline().strip()
    enc = bytes.fromhex(enc.split(" = ")[1].strip())
    pubkey = f.readline().strip()
    signs = f.readlines()

for sign_raw in signs:
    sig = bytes.fromhex(sign_raw.split(" = ")[1].strip())
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    raw_sign.append((r, s, None))

print(len(raw_sign))

for shift in range(105):
    print("Shift:", shift)
    signs = []

    mask = 2**256-1
    raw_sign_shift = raw_sign[shift:]
    e = 523292266480032572263097387253846278739400489039

    for i in range(31):
        if i != 30:
            r, s, k = raw_sign_shift[i * 105+80]
            
            e0 = Fn(e) - s * mask
            r0 = Fn(r)
            s0 = Fn(s) * 8
            # k0 = Fn(Fn(k) - mask)/8
            # assert ZZ(n - k0) < 2 ** 250, (bin(k), k0, n)
            # assert (s0 * k0 - (e0 + d * r0)) == 0
            k0 = None
            signs.append((r0, s0, e0, k0))
        r, s, k = raw_sign_shift[i * 105 + 40]
        e0 = Fn(e) - s * mask
        r0 = Fn(r)
        s0 = Fn(s) * 8
        # k0 = Fn(Fn(k) - mask)/8
        # assert ZZ(n - k0) < 2 ** 250, (bin(k), k0, n)
        # assert (s0 * k0 - (e0 + d * r0)) == 0
        k0 = None
        signs.append((r0, s0, e0, k0))
        r, s, k = raw_sign_shift[i * 105 + 24]
        e0 = Fn(e) - s * mask
        r0 = Fn(r)
        s0 = Fn(s) * 4
        # k0 = Fn(Fn(k) - mask)/4
        # assert ZZ(n - k0) < 2 ** 250, (bin(k), k0, n)
        # assert (s0 * k0 - (e0 + d * r0)) == 0
        k0 = None
        signs.append((r0, s0, e0, k0))


    # e = hashit("4389430897")

    r0, s0, e0, k0 = signs[0]


    u0 = ZZ(s0/r0)
    e0 = ZZ(Fn(e0)/r0)
    # assert (u0*k0 - (e0 + d)) % n == 0

    pairs = []
    iter = 90
    ks = []
    for i in range(iter):
        # r, s, k = ecdsa_sign(d, e)
        r, s, e, k = signs[i+1]
        
        e_tmp = ZZ(Fn(e)/s)
        u_tmp = ZZ(r/s)
        # k == e_tmp + d * u_tmp
        # assert (k - e_tmp - d * u_tmp) % n == 0
        e_tmp2 = e0 * u_tmp - e_tmp
        u_tmp2 = u0 * u_tmp
        # u_tmp2 * k0 == e_tmp2 + k
        # assert (u_tmp2 * k0 - e_tmp2 - k) % n == 0
        pairs.append((e_tmp2-2**249, u_tmp2))
        ks.append(k)

    target, u = zip(*pairs)
    target = vector(ZZ, [0] + list(target))
    u = vector(ZZ, u)
    M = block_matrix(ZZ, [[1, matrix(u)], [zero_matrix(iter, 1), identity_matrix(iter) * n]])
    M = block_matrix(ZZ, [[2**280, matrix(target)], [zero_matrix(iter+1, 1), M]])
    M = flatter(M)
    v = M[-1]

    suc = True
    for i in range(iter):
        guess_k = 2**249 + v[i+2]
        if not (guess_k > 0 and guess_k < 2**252):
            suc = False
            break
    if suc:
        print("Success")
        for i in range(iter):
            guess_k = 2**249 + v[i+2]
            # print(hex(guess_k), int(guess_k).bit_count())
    else:
        continue

    k1 = 2**249 + v[2]
    r1, s1, e1, _ = signs[1]
    d = -(e1 + k1 * s1) * inverse_mod(r1, n) % n

    ks = []
    for r, s, k0 in raw_sign:
        k = (523292266480032572263097387253846278739400489039 + r * d) * pow(s, -1, n) % n
        if k0 is not None:
            assert k == k0
        ks.extend(bin(k)[2:].zfill(256))
    ks = [int(x) for x in ks]

    mods = []
    for p in prime_range(3, 196):
        for i in range(1, p+1):
            suc = True
            for j in range(p*512):
                if j % p == p-i and ks[j] == 0:
                    suc = False
                    break
            if suc:
                mods.append((i, p))
                break
    print(mods)
    rs, ms = zip(*mods)
    rs = list(rs)
    ms = list(ms)
    a = crt(rs, ms)

    print(a, d)
    key = (int(d) ^ int(a)).to_bytes(32, "big")
    print(AES.new(key, AES.MODE_ECB).decrypt(enc))
    break





