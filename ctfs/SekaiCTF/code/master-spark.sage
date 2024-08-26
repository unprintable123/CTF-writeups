from pwn import *
import os

context.log_level = 'debug'

used_primes = set()

def sample_p():
    global used_primes
    def sample_new_prime(r):
        while True:
            p = random_prime(r)
            if p == 2:
                continue
            if p not in used_primes:
                return p

    while True:
        plist = []
        for _ in range(9):
            p = sample_new_prime(512)
            plist.append(p)
        if len(set(plist)) != 9:
            continue
        p0 = sample_new_prime(2**16)
        if p0 in plist:
            continue
        plist.append(p0)
        plist.append(p0)
        q = 4*prod(plist) - 1
        if is_prime(q) and ((q + 1) // 4) % 2 == 1 and q.bit_length() <= 96:
            used_primes = used_primes.union(plist)
            print(q.bit_length())
            return q

# io = process(['sage', 'challenge.sage'])
# = ncat --ssl master-spark.chals.sekai.team 1337
io = remote('master-spark.chals.sekai.team', 1337, ssl=True)
pow = io.recvline().split(b"work:")[1].strip()
print(pow)
sign = input()
io.sendline(sign.encode())

def get_montgomery(Fp2, G):
    A = (G[1]**2 - G[0]**3 - G[0]) / (G[0]**2)
    return EllipticCurve(Fp2, [0, A, 0, 1, 0])

modlist = []

def get_PQ(p):
    Fp = GF(p)
    Fp2.<j> =  GF(p ^ 2, modulus=x ^ 2 + 1)

    io.recvuntil(b'input your prime number or secret > ')
    io.sendline(str(p).encode())
    P0 = eval(io.recvline().strip())
    Q0 = eval(io.recvline().strip())
    E = get_montgomery(Fp2, P0)
    P = E(*P0)
    Q = E(*Q0)
    dlog = Q.log(P)
    order = P.order()//4
    print(order.bit_length())
    modlist.append((dlog, order))

for _ in range(6):
    get_PQ(sample_p())

rs, ps = zip(*modlist)
rs = list(rs)
ps = list(ps)

for u in range(2**len(rs)):
    new_rs = [(-1)**((u >> i) & 1) * r for i, r in enumerate(rs)]
    secret = crt(new_rs, ps)
    if secret.bit_length() <= 256:
        print(secret)
        io.sendline(str(secret).encode())

io.interactive()



