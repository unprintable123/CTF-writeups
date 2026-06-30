from sage.all import ZZ, QQ, GF, randint, vector, sqrt, round, random_prime, random_matrix, block_matrix, save, load
from utils import sample_unimodular, sample_discrete_gaussian, sample_trig_sym_matrix, closest_congruent, four_squares
from hashlib import sha256
import random

class Signature:
    def __init__(self, m=128, k=8, B1=2**80, B0=2**40):
        self.m = m
        self.k = k
        self.n = m + 2*k
        self.B1 = B1
        self.B0 = B0
        
        self.pk = None
        self.sk = None

    def keygen(self):
        m, k, B1, B0 = self.m, self.k, self.B1, self.B0
        
        p = random_prime(B1, lbound=B1//2)
        q = random_prime(B1, lbound=B1//2)
        M1, M2 = [random_matrix(ZZ, m, k, x=-B1//m, y=B1//m) for _ in range(2)]
        for j in range(k):
            for i in range(4):
                M2[i, j] = 0

        M0 = (M1 * M1.transpose() / p + M2 * M2.transpose() / q).apply_map(round) + sample_trig_sym_matrix(m, diag_bound=round(sqrt(B0)))
        
        M = block_matrix(ZZ, [
            [p, 0, M1.T],
            [0, q, M2.T],
            [M1, M2, M0]
        ])

        U, U_inv = sample_unimodular(self.n, steps=40)
        M = U.transpose() * M * U
        
        self.pk = M
        self.sk = {
            'p': p,
            'q': q,
            'M0': M0,
            'M1': M1,
            'M2': M2,
            'U': U,
            'U_inv': U_inv
        }
        return self.pk, self.sk

    def sign(self, message: bytes):
        if self.sk is None:
            raise ValueError("Secret key not found.")
        t = int.from_bytes(b"\x01"+sha256(message).digest(), 'big')
        u = round(sqrt(t//(2*self.k*self.B1)))

        p, q = self.sk['p'], self.sk['q']
        M1, M2, M0 = self.sk['M1'], self.sk['M2'], self.sk['M0']
        x1 = sample_discrete_gaussian(self.m, u)

        x2 = vector(ZZ, x1[8:])
        q_selected = random.sample(range(self.k), 4)
        M2K = M2[4:8, q_selected].change_ring(GF(q))
        xq = M2K.solve_left(x2*M2[8:, q_selected]).change_ring(ZZ)
        for i in range(4):
            x1[4+i] = closest_congruent(x1[4+i], q, -xq[i])
        
        x2 = vector(ZZ, x1[4:])
        p_selected = random.sample(range(self.k), 4)
        M1K = M1[:4, p_selected].change_ring(GF(p))
        xp = M1K.solve_left(x2*M1[4:, p_selected]).change_ring(ZZ)
        for i in range(4):
            x1[i] = closest_congruent(x1[i], p, -xp[i])
        
        x1 = vector(ZZ, x1)
        c1 = x1*M1
        c2 = x1*M2
        o1 = (x1*M1[:, p_selected] / p).change_ring(ZZ)
        o2 = (x1*M2[:, q_selected] / q).change_ring(ZZ)
        
        t1 = t - x1 * M0 * x1 + o1 * o1 * p + o2 * o2 * q
        assert t1 > 0
        
        while True:
            t0 = t1
            d1 = sample_discrete_gaussian(self.k, u)
            d2 = sample_discrete_gaussian(self.k, u)
            for i in range(self.k):
                if i not in p_selected:
                    t0 -= d1[i] * d1[i] * p + 2 * d1[i] * c1[i]
                if i not in q_selected:
                    t0 -= d2[i] * d2[i] * q + 2 * d2[i] * c2[i]
            if t0 > 0:
                break
        
        a = t0 * pow(p, -1, q) % q + q * randint(0, t0 // (p*q))
        b = (t0 - a * p) // q
        assert a * p + b * q == t0

        x0p = vector(ZZ, four_squares(a)) - o1
        x0q = vector(ZZ, four_squares(b)) - o2
        for idx, j in enumerate(p_selected):
            d1[j] = x0p[idx]
        for idx, j in enumerate(q_selected):
            d2[j] = x0q[idx]

        x = vector(ZZ, d1 + d2 + x1.list())
        
        U_inv = self.sk['U_inv']
        signature = (U_inv * x)
        assert signature * self.pk * signature == t
        return signature.list()

    def verify(self, message: bytes, signature: list[int]):
        if self.pk is None:
            raise ValueError("Public key not found.")
        t = int.from_bytes(b"\x01"+sha256(message).digest(), 'big')
        signature = vector(ZZ, signature)
        return signature * self.pk * signature == t

    def save(self, pk_path, sk_path):
        if self.pk is None:
            self.keygen()
            
        common_params = {'m': self.m, 'B1': self.B1, 'B0': self.B0}
        pk_data = {
            'params': common_params,
            'pk': self.pk
        }
        save(pk_data, pk_path)

        sk_data = {
            'params': common_params,
            'pk': self.pk,
            'sk': self.sk
        }
        save(sk_data, sk_path)

    @classmethod
    def load(cls, filename):
        loaded_data = load(filename)
        params = loaded_data['params']
        
        instance = cls(m=params['m'], B1=params['B1'], B0=params['B0'])
        instance.pk = loaded_data['pk']
        instance.sk = loaded_data.get('sk', None)
        
        return instance

if __name__ == "__main__":
    sig = Signature()
    sig.keygen()
    s = sig.sign(b"hello world")
    assert sig.verify(b"hello world", s)