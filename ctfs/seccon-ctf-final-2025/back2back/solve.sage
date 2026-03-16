from pwn import *
from params import *
import re
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import os
from Crypto.Util.number import getPrime
from tqdm import tqdm
io = process(['sage', 'chall.sage'])

x=var('x')

class Params:
    def __init__(self, l_primes, l_exps, q_primes, q_exps, g0, g1, known_cofactor=None):
        self.l_primes = l_primes
        self.l_exps = l_exps
        self.q_primes = q_primes
        self.q_exps = q_exps

        self.A = prod(l ^ e for l, e in zip(l_primes, l_exps))
        self.B = prod(q ^ e for q, e in zip(q_primes, q_exps))
        assert gcd(self.A, self.B) == 1

        self.f = known_cofactor
        self.p = self.A * self.B * self.f - 1
        pari.addprimes(self.p)

        self.Fp2 = GF(self.p ^ 2, name='i', modulus=x ^ 2 + 1)
        self.i = self.Fp2.gen()
        self.E0 = EllipticCurve(self.Fp2, [1, 0])
        self.E0.set_order((self.p + 1) ^ 2)
        assert self.E0.is_supersingular()

        g0 = getPrime(int(self.p).bit_length()) * self.E0(g0[0][0] * self.i + g0[0][1], g0[1][0] * self.i + g0[1][1])
        g1 = getPrime(int(self.p).bit_length()) * self.E0(g1[0][0] * self.i + g1[0][1], g1[1][0] * self.i + g1[1][1])
        self.PA = (self.B * self.f) * g0
        self.QA = (self.B * self.f) * g1
        self.PB = (self.A * self.f) * g0
        self.QB = (self.A * self.f) * g1

        assert (self.A * self.PA).is_zero()
        assert (self.A * self.QA).is_zero()
        assert (self.B * self.PB).is_zero()
        assert (self.B * self.QB).is_zero()

    def _find_cofactor(self):
        f = 1
        while not is_prime(self.A * self.B * f - 1):
            f += 1
        return f

    def __repr__(self):
        A_str = " * ".join(f"{l}^{e}" for l, e in zip(self.l_primes, self.l_exps))
        B_str = " * ".join(f"{q}^{e}" for q, e in zip(self.q_primes, self.q_exps))
        return (f"Params(\n"
                f"  A = {self.A}  ({A_str})\n"
                f"  B = {self.B}  ({B_str})\n"
                f"  f = {self.f}\n"
                f"  p = {self.p}\n"
                f")")

class PublicKey:
    def __init__(self, E, R, S):
        self.E = E
        self.R = R
        self.S = S

    def __repr__(self):
        return (f"Params(\n"
                f"  E = {(self.E.a4(), self.E.a6())}\n"
                f"  R = {self.R.xy()}\n"
                f"  S = {self.S.xy()}\n"
                f")")

params = Params(l_primes, l_exps, q_primes, q_exps, g0, g1, f)
Fp2 = params.Fp2

def parse_fp2_element(s, Fp2):
    return sage_eval(s, locals={'i': params.i})

def parse_pk_block(io):
    """
    解析服务器输出的一个 PublicKey (Params) 块
    """
    io.recvuntil(b"E = (")
    e_raw = io.recvuntil(b")\n", drop=True).decode().split(',')
    a4 = parse_fp2_element(e_raw[0], Fp2)
    a6 = parse_fp2_element(e_raw[1], Fp2)
    E = EllipticCurve(Fp2, [a4, a6])
    
    io.recvuntil(b"R = (")
    r_raw = io.recvuntil(b")\n", drop=True).decode().split(',')
    Rx = parse_fp2_element(r_raw[0], Fp2)
    Ry = parse_fp2_element(r_raw[1], Fp2)
    R = E(Rx, Ry)
    
    io.recvuntil(b"S = (")
    s_raw = io.recvuntil(b")\n", drop=True).decode().split(',')
    Sx = parse_fp2_element(s_raw[0], Fp2)
    Sy = parse_fp2_element(s_raw[1], Fp2)
    S = E(Sx, Sy)
    
    io.recvuntil(b")") # 闭合 Params(
    return E, R, S

alice_pk = parse_pk_block(io)
bob_pk = parse_pk_block(io)
io.recvuntil(b"enc: ")
enc = bytes.fromhex(io.recvline().strip().decode())

def point_to_list(P):
    """将 Sage 点转换为服务器要求的 [x0, x1, y0, y1] 格式"""
    xs = P.xy()[0].list()
    ys = P.xy()[1].list()
    return [int(xs[0]), int(xs[1]) if len(xs)>1 else 0, 
            int(ys[0]), int(ys[1]) if len(ys)>1 else 0]
def get_alice_j(R_pt, S_pt):
    """向服务器发送点并获取 Alice 计算的 j-invariant"""
    io.sendlineafter(b"bob pk list R: ", str(point_to_list(R_pt)).encode())
    io.sendlineafter(b"bob pk list S: ", str(point_to_list(S_pt)).encode())
    res = io.recvline().strip().decode()
    # 解析 Fp2 元素 (可能包含 i)
    return params.Fp2(sage_eval(res, locals={'i': params.i}))

bob_E, bob_RB, bob_SB = bob_pk


A = params.A
N = params.A * params.B
l_primes = params.l_primes + params.q_primes
l_exps = params.l_exps + params.q_exps
k_final = 0
mod_accumulator = 1


print("[*] Starting Adaptive Attack to recover n/m mod A...")

def basis_points(E, A, B, p):
    order = (p + 1)
    f = order // (A * B)

    while True:
        G = f * E.random_point()
        if G.is_zero():
            continue

        P_A = B * G
        P_B = A * G

        if P_A.order() == A and P_B.order() == B:
            return P_A, P_B

for l, e in zip(l_primes, l_exps):
    k_l = 0
    print(f"    Recovering k mod {l}^{e}...")
    for v in range(1, e + 1):
        # 1. 询问 Alice 在当前 l^v 阶下的 j-invariant
        # Alice 计算 j(E_B / <m*R_send + n*S_send>)
        # 我们发送阶为 l^v 的点
        print(f"        Querying Alice for l={l}, v={v}...")
        # R_send = (N // (l^v)) * bob_RB
        # S_send = (N // (l^v)) * bob_SB
        R_send, S_send = bob_E.torsion_basis(l^v)
        target_j = get_alice_j(R_send, S_send)
        
        # 2. 本地枚举可能的系数 d
        found = False
        for d in tqdm(range(l)):
            test_k = k_l + d * (l^(v-1))
            # 这里的原理是：<m*R + n*S> == <R + (n/m)*S>
            # 因为 gcd(m, l) = 1
            P_test = R_send + test_k * S_send
            try:
                # 计算本地同源
                phi_test = bob_E.isogeny(P_test, algorithm = "factored")
                if phi_test.codomain().j_invariant() == target_j:
                    k_l = test_k
                    found = True
                    break
            except:
                continue
        if not found:
            print(f"[!] Error: Could not find digit for l={l}, v={v}")
            break
            
    # 合并不同素因数的结果 (CRT)
    k_final = crt([k_final, k_l], [mod_accumulator, l^e])
    mod_accumulator *= l^e

print(f"[+] Recovered k = n*inv(m) mod A: {k_final}")

# --- 利用 LLL 求解 m, n ---
# 我们知道 n = m * k mod A，且 m, n < A
# 构造格: [ [1, k], [0, A] ]
print("[*] Solving for m, n using LLL...")
L = Matrix(ZZ, [[1, k_final], [0, N]])
shortest_vectors = L.LLL()
print(shortest_vectors)

m, n = 0, 0
for row in shortest_vectors:
    m_try, n_try = abs(row[0]), abs(row[1])
    # 验证是否满足私钥条件（素数，且在 mod A 下比例正确）
    if is_prime(m_try) and is_prime(n_try):
        if (n_try * pow(m_try, -1, N)) % N == k_final:
            m, n = int(m_try), int(n_try)
            break

if m == 0:
    print("[-] Failed to recover m, n. Check LLL or attack logic.")
else:
    print(f"[+] Found Alice secret: m={m}, n={n}")
    
    # --- 解密 Flag ---
    sk_str = str((m, n))
    tmp = sha256(sk_str.encode()).digest()
    key = tmp[:16]
    iv = tmp[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    flag = cipher.decrypt(enc)
    print(flag)







