from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes
from sage.all import *
from pwn  import *

# context.log_level = 'debug'

# FLAG = open('flag.txt', 'rb').read().strip()
FLAG = b'flag{this_is_a_fake_flag_101029837924783253487645667856278}'

# def mask_expr(expr):
#     global e, n
#     assert '**' not in expr, "My computer is weak, I can't handle this insane calculation"
#     assert len(expr) <= 4, "Too long!"
#     assert all([c in r'pq+-*/%' for c in expr]), "Don't try to break me"
#     res = eval(expr)
#     return str(pow(res, e, n))[::2]

get_len = lambda x: len(str(x))

process_cnt = 0
# def sample():
#     global process_cnt
#     process_cnt += 1
#     if process_cnt % 100 == 0:
#         print(f"{process_cnt = }")
#     e = 3
#     p, q = 1, 1
#     while p == q:
#         while (p-1) % e == 0:
#             p = getPrime(513)
#         while (q-1) % e == 0:
#             q = getPrime(513)
#     if p > q:
#         p, q = q, p

#     m = bytes_to_long(FLAG)
#     n = p * q
#     c = pow(m, e, n)
#     return p, q, n, e, c


# def check(p,q,n,e,c):
#     p0 = get_len(pow(p, 3, n))
#     if p0 == 309:
#         return False
#     pq_mod = pow(-q%p, 3, n) # 2*p-q
#     p_q = pow(p-q, 3, n)
#     q1 = pow(-q, 3, n)
#     if get_len(q1) == 309:
#         return False
#     if get_len(pq_mod) == 309:
#         return False
#     if get_len(p_q) == 309:
#         return False
#     return True

# def simulate():
#     while True:
#         p, q, n, e, c = sample()
#         if check(p,q,n,e,c):
#             return p, q, n, e, c
#         # p0 = get_len(pow(p, 3, n))
#         # if p0 != 307:
#         #     continue
#         # print("aaa")

#         # pq_mod = pow(-q%p, 3, n) # 2*p-q
#         # p_q = pow(p-q, 3, n)
#         # q1 = pow(-q, 3, n)
#         # # assert (8*pow(p, 3, n) + q1)%n == pq_mod
#         # if (8*pow(p, 3, n) + q1) > n:
#         #     continue

#         # if get_len(q1)%2 != 0:
#         #     continue
#         # if get_len(pq_mod)%2 != 0:
#         #     continue
#         # if get_len(p_q)%2 != 0:
#         #     continue
#         # print(f"{cnt = }")
#         # break


def solve(p0, p_q, q1, pq_mod):
    guess = [None] * 307

    for i in range(len(p0)):
        guess[2*i] = [int(p0[i])]
    for i in range(153):
        def get_possible_chrs(a, b):
            u = (10+a-b)%10
            if u > 0:
                return [u-1, u]
            else:
                assert u == 0
                return [0, 9]
        guess[2*i+1] = get_possible_chrs(int(p_q[i+1]), int(q1[i+1]))

    for i in range(153):
        ps = guess[2*i+1]
        next_chr = guess[2*i+2][0]
        target = int(pq_mod[i+1])
        base = int(p_q[i+1])
        next_chr_affect = next_chr*7//10
        u = []
        for p in ps:
            if (target - (p*7 + base + next_chr_affect)) % 10 <= 2:
                u.append(p)
        guess[2*i+1] = u

    # for r, pl in zip(str(real_value), guess):
    #     assert int(r) in pl
    if any([len(pl) != 1 for pl in guess]):
        return False, None
    real_p0 = int("".join([str(pl[0]) for pl in guess]))
    return True, real_p0


def get_data():
    global process_cnt
    process_cnt += 1
    if process_cnt % 100 == 0:
        print(f"{process_cnt = }")
    # io = process(["python3", "run.py"])
    # mask-rsa.challs.csc.tf 1337
    io = remote("mask-rsa.challs.csc.tf", 1337)
    io.recvuntil("c = ")
    c = int(io.recvline().strip())

    def mask_expr(expr):
        io.sendline(expr)
        return io.recvline().replace(b"Input your expression in terms of p, q and r: ", b"").strip().decode()
    
    if mask_expr("p//q") != "0":
        p0 = mask_expr("q")
        q1 = mask_expr("-p")
        pq_mod = mask_expr("-p%q")
        p_q = mask_expr("q-p")
    else:
        p0 = mask_expr("p")
        q1 = mask_expr("-q")
        pq_mod = mask_expr("-q%p")
        p_q = mask_expr("p-q")
    print(len(p0), len(q1), len(pq_mod), len(p_q))
    if max(len(p0), len(q1), len(pq_mod), len(p_q)) > 154:
        io.close()
        return None
    io.close()
    return p0.ljust(154, "0"), p_q.ljust(154, "0"), q1.ljust(154, "0"), pq_mod.ljust(154, "0"), c

real_values = []


while len(real_values) < 8:
    # p, q, n, e, c = simulate()
    # print(p,q,n,e,c)
    # assert mask_expr("p//q") == "0", mask_expr("p//q")

    # real_value = pow(p, 3, n)
    # p0 = mask_expr("p").ljust(154, "0")
    # # p1 = mask_expr("-p")
    # # q0 = mask_expr("q")
    # q1 = mask_expr("-q").ljust(154, "0")
    # pq_mod = mask_expr("-q%p").ljust(154, "0") # 2*p-q
    # p_q = mask_expr("p-q").ljust(154, "0")

    data = get_data()
    if data is None:
        continue
    print("data")
    p0, p_q, q1, pq_mod, c = data
    suc, v = solve(p0, p_q, q1, pq_mod)
    if suc:
        print("suc")
        print(v)
        m = bytes_to_long(FLAG)
        assert gcd(m**3-c, v) > 1, f"{c}, {v}"
        real_values.append((c, v))
        print(process_cnt)
        print(real_values)
        cs = [c for c, v in real_values]
        vs = [v for c, v in real_values]
        if len(real_values) == 1:
            u = cs[0]
        else:
            for i in range(1, len(real_values)):
                for j in range(i):
                    ugcd = gcd(vs[i], vs[j])
                    if ugcd != 1:
                        vs[i] //= ugcd
                        vs[j] //= ugcd
            u = crt(cs, vs)
        R = PolynomialRing(Zmod(prod(vs)), 'x')
        x = R.gen()
        f = x**3 - u
        t = f.small_roots(X=2**(500*len(real_values)//3), beta=0.5)
        if len(t) > 0:
            print(t)
            print("found")
            print(t[0])
            print(long_to_bytes(int(t[0])))
            break
        break
