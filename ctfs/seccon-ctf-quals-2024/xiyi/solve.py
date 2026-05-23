from subprocess import check_output
from sage.all import *
from sage.groups.generic import bsgs
from tqdm import tqdm
from pwn import remote, process

def run_kangaroo(target, g, order, bound=None, num_retry=3):
    # solve target = g**k mod p
    if bound is None:
        bound = order
    assert order % 2 == 1
    p = g.parent().characteristic()
    inp = f"{p} {g} {order} {target} {bound}\n"
    print(f"Running kangaroo with {bound.bit_length()} bits...")
    print(inp)
    ret = None
    for _ in range(num_retry):
        try:
            ret = check_output("./kangaroo_gpu", input=inp.encode(), shell=True).decode()
            assert "Solution:" in ret
            break
        except Exception as e:
            print(e)
            continue
    assert ret is not None, "Kangaroo failed"
    print(ret)
    k = ret.split("Solution:")[1]
    k = k.split("\n")[0]
    return ZZ(k)

def dlp_generic(target, g, order, max_bound, num_retry=3):
    if max_bound.bit_length() > 32:
        return run_kangaroo(target, g, order, max_bound, num_retry)
    else:
        return bsgs(g, target, bounds=(ZZ(0), max_bound))

def dlp_prime(target, g, order, num_retry=3):
    if order.bit_length() > 34:
        return run_kangaroo(target, g, order, num_retry=num_retry)
    else:
        os = matrix(ZZ, [[order, 1]])
        return pari(target).znlog(pari(g), pari([order, os])).sage()

def dlp_primepower(target, g, prime, n, num_retry=3):
    order = prime**n
    k = 0
    g0 = g ** (order // prime)
    for i in range(n):
        t0 = target * (g**(-k))
        t0 = t0 ** (prime**(n-1-i))
        assert t0 ** prime == 1
        k += dlp_prime(t0, g0, prime, num_retry) * prime**i
    return k

def dlp_main(target, g, order, max_bound, factors, num_retry=3):
    # solve target = g**k mod p
    cur_bound = max_bound
    mods = []
    for prime, n in factors:
        if cur_bound <= 10:
            break
        if prime > cur_bound: # too large, fall back to generic
            break
        mod = prime**n
        ord_ = order // mod
        g0 = g ** ord_
        t0 = target ** ord_
        cur_bound = cur_bound // mod
        k_ = dlp_primepower(t0, g0, prime, n, num_retry)
        mods.append((k_, mod))
    rs, ms = zip(*mods)
    k0 = crt(list(rs), list(ms))
    MOD = prod(ms) # k = k0 + ? * MOD
    g1 = g ** MOD
    t1 = target * (g ** (-k0))
    k1 = dlp_generic(t1, g1, order // MOD, cur_bound+1, num_retry)
    return k0 + k1 * MOD

def dlp(target, g, order=None, bounds=None, known_factors=None, num_retry=3):
    """
    Solve DLP for target = g**k mod p
    
    - **order**: order of g. A multiple of the order (e.g. p-1) is also accepted.
    - **bounds**: The bound for k. If None, it will be set to `order-1`. 
                 If integer, search range is [0, bound]. 
                 If list/tuple, represents an interval [min, max].
    - **known_factors**: List of known factors of order. The rest part of the order will be handled by generic method.
                        Either (prime, exponent) pairs or prime lists are accepted.
    - **num_retry**: Number of retries when kangaroo fails.
    """
    assert g.parent().is_prime_field()
    p = g.parent().characteristic()
    if order is None:
        order = p-1
    else:
        order = ZZ(order)
    if bounds is None:
        bounds = order
    if known_factors is None:
        known_factors = list(factor(order, algorithm="ecm"))
    if isinstance(known_factors[0], (list, tuple)):
        known_primes = [p for p, _ in known_factors]
    else:
        known_primes = known_factors
    if 2 not in known_primes:
        known_primes.append(2)
    assert g ** order == 1
    known_primes.sort()
    for p in known_primes:
        while order % p == 0 and (g ** (order // p)) == 1:
            order = order // p
    assert g ** order == 1
    factors = []
    ord_ = order
    for p in known_primes:
        if ord_ % p != 0:
            continue
        v = ord_.valuation(p)
        factors.append((p, v))
        ord_ = ord_ // (p**v)
    if ord_ > 1:
        factors.append((ord_, 1))
    factors.sort()
    print(factors)
    if bounds is None:
        bounds = (0, order-1)
    elif isinstance(bounds, (list, tuple)):
        bounds = tuple(bounds)
    else:
        bounds = (0, int(bounds))
    min_bound, max_bound = bounds
    t2 = target * (g ** (-min_bound))
    range = max_bound - min_bound
    return min_bound + dlp_main(t2, g, order, range, factors, num_retry), factors

import json
from secrets import randbelow

from lib2 import Cryptosystem, Privkey, Pubkey, Ct # same as lib.py
from params import L, M, N

p = 470772889347891753894848105243789217710301326704247389714521154467591283889037042443973128895041119713324021962506767036488831747747963841111160849037254561 # (2^1308+1)
q = 731433453306625773851831070026391128383727479375152752977676902094814479855682993608187229204658713734108641142148010876470120999557683935590321341245075861 # (2^2490+1)

p1_factors = [(2, 5), (3, 3), (5, 1), (109, 1), (457456471313, 1), (53400322888084232503, 1), (4952131943166985961003171, 1), (12483277974290346429122493663434783301283, 1), (662043754266558743926932151479961636112025140409089081, 1)]
q1_factors = [(2, 2), (3, 1), (5, 1), (61, 1), (83, 1), (2099, 1), (14071, 1), (361728968932127, 1), (225369400669558848086892569194138533812747585329213772218859604310602106229150875171288346031013036088614600109065387761801873239, 1)]
n_factors = list(sorted(set([pf[0] for pf in p1_factors] + [qf[0] for qf in q1_factors])))+[p]
p_used = [2, 3, 457456471313, 53400322888084232503]
q_used = [61, 2099, 14071, 361728968932127]
p_unused = prod([4952131943166985961003171, 12483277974290346429122493663434783301283, 662043754266558743926932151479961636112025140409089081])
q_unused = 225369400669558848086892569194138533812747585329213772218859604310602106229150875171288346031013036088614600109065387761801873239

n = p**2 * q
order = p*lcm(p-1,q-1)

for x in range(2, 10000):
    x = mod(x, n)
    assert x ** order == 1
    good = True
    for p0 in n_factors:
        if (x ** (order // p0)) == 1:
            good = False
            break
    if good:
        gx = int(x)
        break

bad_g = mod(n // 2, p*q)
bad_g_order = 1085640
assert bad_g ** bad_g_order == 1

priv_key = Privkey(p, q, Pubkey(n))

io = process(['sage', 'server.py'])

# initialize
C = Cryptosystem.from_privkey(priv_key)
assert C.privkey is not None
enc_xs = [Ct(pow(gx, 281**i, n)) for i in range(L)]

# 1: (client) --- n, enc_xs ---> (server)
io.sendlineafter(b"> ", json.dumps({"n": n, "enc_xs": enc_xs}).encode())

def decrypt_correct(c: int) -> int:
    a = C.L(pow(c, p - 1, p**2))
    b = C.L(pow(gx, p - 1, p**2))
    return a * pow(b, -1, p) % p

# 3: (server) --- enc_alphas, beta_sum_mod_n ---> (client)
params = json.loads(io.recvline().strip().decode())
enc_alphas, beta_sum_mod_n = params["enc_alphas"], params["beta_sum_mod_n"]
beta_sum_mod_n = decrypt_correct(n//2) * beta_sum_mod_n % p
alphas = [decrypt_correct(enc_alpha) for enc_alpha in enc_alphas]
alpha_sum = sum(alphas) % p
inner_product = (alpha_sum + beta_sum_mod_n) % p
print(f"{inner_product = }")

ys = []
for i in tqdm(range(L)):
    target = pow(enc_alphas[i], bad_g_order, p*q)
    base = pow(gx, 281**i, n)
    base = pow(base, bad_g_order, p*q)
    # base ** y_i == target
    target2 = pow(target, p_unused * q_unused, p*q)
    base2 = pow(base, p_unused * q_unused, p*q)
    
    p_i, f_p = dlp(mod(target2, p), mod(base2, p), (p-1)//p_unused, known_factors=p1_factors)
    q_i, f_q = dlp(mod(target2, q), mod(base2, q), (q-1)//q_unused, known_factors=q1_factors)
    # print(p_i, f_p)
    # print(q_i, f_q)
    mod1 = prod([pf[0]**pf[1] for pf in f_p])
    mod2 = prod([qf[0]**qf[1] for qf in f_q])
    ci = (inner_product - sum([ys[j] * 281**j for j in range(i)]))
    assert ci % (281**i) == 0
    inner_product_i = ci // (281**i)
    y_i_0 = crt([p_i, q_i, inner_product_i%281], [mod1, mod2, 281])
    MOD = mod1 * mod2 * 281
    base3 = mod(base, p) ** ((p-1)//p_unused)
    target3 = mod(target, p) ** ((p-1)//p_unused)
    target3 = target3 / (base3 ** y_i_0)
    base3 = base3 ** MOD
    y_i_1 = dlp_generic(target3, base3, p_unused, M//MOD)
    y_i = y_i_0 + y_i_1 * MOD
    print(f"{i = }, {y_i = }")
    ys.append(int(y_i))




# If, by any chance, you can guess ys, send it for the flag!
io.sendlineafter(b"> ", json.dumps({"ys": ys, "p": C.privkey.p, "q": C.privkey.q}).encode())
print(io.recvline().strip().decode())  # Congratz! or Wrong...
print(io.recvline().strip().decode())  # flag or ys