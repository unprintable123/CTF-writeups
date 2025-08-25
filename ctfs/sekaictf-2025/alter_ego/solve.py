from sage.all import *
from pwn import *
from tqdm import tqdm

MI = 3
KU = 9
MIKU = 39

ells = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 587]
p = 4 * prod(ells) - 1

Fp = GF(p)
F = GF(p**2, modulus=[1, 0, 1], names='i')
i = F.gen(0)

E0 = EllipticCurve(F, [0, 0, 0, 1, 0])

io = process(['sage', 'chall.sage'])
# io = remote('alter-ego.chals.sekai.team', 1337, ssl=True)

def group_action(E0, priv):
    E = E0
    es = priv[:]
    while any(es):
        x = Fp.random_element()
        P = E.lift_x(x)
        s = 1 if P[1] in Fp else -1
        S = [i for i, e in enumerate(es) if sign(e) == s and e != 0]
        k = prod([ells[i] for i in S])
        Q = ((p + 1) // k) * P
        
        for i in S:
            R = (k // ells[i]) * Q
            if R.is_zero():
                continue
            phi = E.isogeny(R)
            E = phi.codomain()
            Q = phi(Q)
            es[i] -= s
            k //= ells[i]
    return E

def read_curve():
    io.recvuntil(b'final_a2 = ')
    a2 = int(io.recvline().strip())
    E2 = EllipticCurve(F, [0, a2, 0, 1, 0])
    E2.set_order((p + 1)**2)
    return E2

def read_point(EC):
    io.recvuntil(b'_final_G=')
    point_str = io.recvline().strip().decode()
    x, z = eval(point_str.replace(':', ', '))
    x = F(x)
    z = F(z)
    G = EC.lift_x(x / z)
    return G

def get_orders(G):
    EC = G.curve()
    gen1 = gen2 = None
    while gen1 is None or gen2 is None:
        x0 = Fp.random_element()
        P = EC.lift_x(x0)
        is_gen = True
        for ell in ells:
            P1 = ((p + 1) // ell) * P
            if P1.is_zero():
                is_gen = False
                break
        if not is_gen:
            continue
        if P.y() in Fp:
            gen1 = P
        else:
            gen2 = P
    pairing1 = G.weil_pairing(gen1, p+1)
    pairing2 = G.weil_pairing(gen2, p+1)
    return pairing2.multiplicative_order(), pairing1.multiplicative_order()

orders = []
curves = []

for k in tqdm(range(MIKU)):
    cur_E = read_curve()
    curves.append(cur_E)
    G = read_point(cur_E)
    orders.append(get_orders(G))
    if k < 28:
        io.sendline(", ".join(["-1"]*len(ells)).encode())
    else:
        io.sendline(", ".join(["0"]*len(ells)).encode())
io.recvuntil(b"FIN!\n")

guess_priv = []

for ell in ells:
    left = MI + KU
    right = MI * KU
    for i, (o1, o2) in enumerate(orders):
        if o1 % ell == 0:
            right = min(right, i)
        if o2 % ell == 0:
            left = max(left, i)
    guess_priv.append((left, right-left))

print("guess_priv =", guess_priv)

E1 = curves[0]
G0 = E0.random_point()

left, offset = zip(*guess_priv)
left = list(left)
offset = list(offset)

print(offset)

def gen_all_possible_privs(offset):
    if len(offset) == 1:
        for i in range(offset[0]+1):
            yield [i]
    else:
        for os in gen_all_possible_privs(offset[1:]):
            for i in range(offset[0]+1):
                yield [i] + os

E1_base = group_action(E0, left)
print(E1_base)

def check():
    for os in gen_all_possible_privs(offset):
        E1_new = group_action(E1_base, os).montgomery_model()
        # print(E1_new.j_invariant(), E1.j_invariant(), E1_new, os)
        if E1_new.j_invariant() == E1.j_invariant():
            real_priv = [l + o for l, o in zip(left, os)]
            print("Found valid private key:", real_priv)
            return real_priv

real_priv = check()
real_priv2 = [x - 36 for x in real_priv]
io.sendline(", ".join(map(str, real_priv2)).encode())

io.recvuntil(b'There you are...')
io.recvline()
print(io.recvline().strip().decode())





