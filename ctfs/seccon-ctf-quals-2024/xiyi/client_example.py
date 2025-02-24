import json
from secrets import randbelow
from sage.all import *

from pwn import remote, process

from lib import Cryptosystem, Privkey, Pt, Pubkey
from params import L, M, N




# initialize
xs = [Pt(pow(257, i)) for i in range(L)]
print(f"{xs = }")
p = 731433453306625773851831070026391128383727479375152752977676902094814479855682993608187229204658713734108641142148010876470120999557683935590321341245075861
q = 470772889347891753894848105243789217710301326704247389714521154467591283889037042443973128895041119713324021962506767036488831747747963841111160849037254561
 
fac_p = [[2,2],[3,1],[5,1],[61,1],[83,1],[2099,1],[14071,1],[361728968932127,1],[225369400669558848086892569194138533812747585329213772218859604310602106229150875171288346031013036088614600109065387761801873239,1]]
fac_q = [[2,5],[3,3],[5,1],[109,1],[457456471313,1],[53400322888084232503,1],[4952131943166985961003171,1],[12483277974290346429122493663434783301283,1],[662043754266558743926932151479961636112025140409089081,1]]

n = p**2 * q

ord1 = 4980
ord2 = 2616

fake_g = n//2
assert pow(fake_g, ord1, p) == 1
assert pow(fake_g, ord2, q) == 1
assert p.bit_length() == q.bit_length() == N

# io = remote("localhost", 13333)
io = process(["python3", "server.py"])

g = randbelow(n)
while True:
    is_primitive = True
    for c, d in fac_p:
        o = (p-1) // c
        if pow(g, o, p) == 1:
            is_primitive = False
            break
    for c, d in fac_q:
        if c == 2 or c == 3:
            continue
        o = (q-1) // c
        if pow(g, o, q) == 1:
            is_primitive = False
            break
    if is_primitive:
        break
    g = randbelow(n)
print(f"{g = }")


C = Cryptosystem.from_privkey(Privkey(p=p, q=q, pub=Pubkey(n=n)))
assert C.privkey is not None
enc_xs = [pow(g, x, n) for x in xs]

def decrypt(enc):
    a = C.L(pow(enc, p - 1, p**2))
    b = C.L(pow(g, p - 1, p**2))
    return a * pow(b, -1, p) % p

enc_base = decrypt(C.encrypt(Pt(1)))


# 1: (client) --- n, enc_xs ---> (server)
io.sendlineafter(b"> ", json.dumps({"n": n, "enc_xs": enc_xs}).encode())

# 3: (server) --- enc_alphas, beta_sum_mod_n ---> (client)
params = json.loads(io.recvline().strip().decode())
enc_alphas, beta_sum_mod_n = params["enc_alphas"], params["beta_sum_mod_n"]
alphas = [decrypt(enc_alpha) for enc_alpha in enc_alphas]
alpha_sum = sum(alphas) % p
inner_product = (alpha_sum + beta_sum_mod_n * enc_base) % p
print(f"{inner_product = }")


# If, by any chance, you can guess ys, send it for the flag!
ys = [0] * L
io.sendlineafter(b"> ", json.dumps({"ys": ys, "p": C.privkey.p, "q": C.privkey.q}).encode())
print(io.recvline().strip().decode())  # Congratz! or Wrong...
ys = eval(io.recvline().strip().decode().split(" = ")[1])

def dlog(target, base, ord, mod):
    r = round(ZZ(ord).sqrt().n())
    table = {}
    u = 1
    h = (2**127-1)
    for i in range(r+1000):
        table[int(u&h)] = i
        u = u * base % mod
    u = target
    inv_r = pow(base, -r, mod)
    for i in range(r+1000):
        key = int(u&h)
        if key in table:
            return i * r + table[key]
        u = u * inv_r % mod
    raise ValueError

guess_ys = []

rest_inner_product = inner_product
for i in range(L):
    base = pow(g, xs[i], n)
    mods = [(rest_inner_product % 257, 257)]
    for c, d in fac_p:
        if ord1 % c == 0:
            continue
        if c.bit_length() > 70:
            continue
        o = (p-1) // c
        G = pow(base, o, p)
        assert G != 1
        T = pow(enc_alphas[i], o, p)
        G = mod(G, p)
        T = mod(T, p)
        print(T, G, c, p)
        # b = discrete_log(T, G, ord=c)
        b = 0
        mods.append((b, c))
        print(f"{b = }", c)
    for c, d in fac_q:
        if ord2 % c == 0:
            continue
        if c.bit_length() > 70:
            continue
        assert (q-1) % c == 0
        o = (q-1) // c
        G = pow(base, o, q)
        assert G != 1
        T = pow(enc_alphas[i], o, q)
        # G = mod(G, q)
        # T = mod(T, q)
        # b = discrete_log(T, G, ord=c)
        print(T, G, c, q)
        # b = dlog(T, G, ord=c, mod=q)
        b = 0
        mods.append((b, c))
        print(f"{b = }", c)
    rs, ms = zip(*mods)
    rs = list(rs)
    ms = list(ms)
    print(rs, ms)
    f_base = crt(rs, ms)
    print(f_base)
    
    MM = prod(ms)
    print(MM.bit_length())
    
    assert pow(base, ys[i]*ord2, q) == pow(enc_alphas[i], ord2, q)
    assert ys[i] % prod(ms) == f_base
    
    base2 = (mod(base, q) ** MM) ** ord2
    target = (mod(enc_alphas[i], q) / (mod(base, q)**f_base)) ** ord2
    print(target, base2)
    mul = discrete_log(target, base2, ord=ZZ(12483277974290346429122493663434783301283), bounds=(0, 2**64))
    print(f"{mul = }")
    y = f_base + mul * MM
    
    assert y == ys[i], (y, ys[i])
    guess_ys.append(y)
    rest_inner_product -= y
    assert rest_inner_product % 257 == 0
    rest_inner_product //= 257







