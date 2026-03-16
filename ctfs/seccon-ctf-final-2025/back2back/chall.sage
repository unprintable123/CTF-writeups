import ast
from params import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from hashlib import sha256
import os
from Crypto.Util.number import getPrime

FLAG = os.getenv("FLAG", "SECCON{test_flag}").encode()

proof.all(False)


def basis_points(E, A, B, p):
    order = (p + 1)**2
    f = order // (A * B)

    while True:
        G = f * E.random_point()
        if G.is_zero():
            continue

        P_A = B * G
        P_B = A * G

        if P_A.order() == A and P_B.order() == B:
            return P_A, P_B


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


class User:
    def __init__(self, params, role):
        assert role in ('alice', 'bob'), "role must be 'alice' or 'bob'"
        self.params = params
        self.role = role
        if role == 'alice':
            self._P_own = params.PA
            self._Q_own = params.QA
            self._own_ord = params.A
            self._P_other = params.PB
            self._Q_other = params.QB
            self._mask_mod = params.B
        else:
            self._P_own = params.PB
            self._Q_own = params.QB
            self._own_ord = params.B
            self._P_other = params.PA
            self._Q_other = params.QA
            self._mask_mod = params.A

        self._sk = None

    def keygen(self):
        params = self.params
        N = self._own_ord

        while True:
            m = randrange(0, N)
            if is_prime(m):
                break
        while True:
            n = randrange(0, N)
            if is_prime(n):
                break

        R_own = m * self._P_own + n * self._Q_own
        self._sk = (m, n)
        self._degree = R_own.order()

        phi = params.E0.isogeny(R_own, algorithm="factored")
        E = phi.codomain()

        phi_P = phi(self._P_other)
        phi_Q = phi(self._Q_other)

        mask = self._random_unit(self._mask_mod)
        self._mask = mask

        return PublicKey(E, mask * phi_P, mask * phi_Q)

    def shared_key(self, other_pk):
        assert self._sk is not None, "Call keygen() first"
        m, n = self._sk

        R_img = m * other_pk.R + n * other_pk.S
        E_shared = other_pk.E.isogeny(R_img, algorithm="factored").codomain()
        return E_shared.j_invariant()

    @staticmethod
    def _random_unit(N):
        u = randrange(1, N)
        while gcd(u, N) != 1:
            u = randrange(1, N)
        return u

    @property
    def secret_degree(self):
        assert self._sk is not None, "Call keygen() first"
        return self._degree


def chall():
    params = Params(l_primes, l_exps, q_primes, q_exps, g0, g1, f)

    alice = User(params, role='alice')
    alice_pk = alice.keygen()
    bob = User(params, role='bob')
    bob_pk = bob.keygen()
    print(alice_pk)
    print(bob_pk)

    tmp = sha256(str(alice._sk).encode()).digest()
    key = tmp[:16]
    iv = tmp[16:]
    print(f"enc: {AES.new(key, AES.MODE_CBC, iv=iv).encrypt(pad(FLAG, AES.block_size)).hex()}")

    while True:
        bob_pk_list_R = ast.literal_eval(input("bob pk list R: "))
        bob_pk_list_S = ast.literal_eval(input("bob pk list S: "))

        bob_pk_R = (bob_pk_list_R[1] * params.i + bob_pk_list_R[0], bob_pk_list_R[3] * params.i + bob_pk_list_R[2])
        bob_pk_S = (bob_pk_list_S[1] * params.i + bob_pk_list_S[0], bob_pk_list_S[3] * params.i + bob_pk_list_S[2])

        bob_pk = PublicKey(bob_pk.E, bob_pk.E(bob_pk_R), bob_pk.E(bob_pk_S))
        shared = alice.shared_key(bob_pk)
        print(shared)
    


chall()
