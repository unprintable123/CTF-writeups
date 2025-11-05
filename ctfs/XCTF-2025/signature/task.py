from sage.all import *
from hashlib import sha256
from Crypto.Util.number import getPrime
import random
import signal

class QCG:
    def __init__(self, a, b, c, m, seed):
        self.a = a
        self.b = b
        self.c = c
        self.m = m
        self.state = seed

    def next(self):
        self.state = (self.a * self.state**2 + self.b * self.state + self.c) % self.m
        # assert self.state % 3 == 0
        return self.state


class Signature:
    def __init__(self, q, N, qcg):
        self.q = q
        self.N = N
        self.qcg = qcg

        Zx = PolynomialRing(ZZ, "x")
        x = Zx.gens()[0]
        self.R = Zx.quotient(x**self.N + 1)

        Zqx = PolynomialRing(Zmod(self.q), "x")
        x = Zqx.gens()[0]
        self.Rq = Zqx.quotient(x**self.N + 1)

        self.keyGen()

    def keyGen(self):
        while True:
            f = [self.discrete_gaussian_sample(0, 1, 1) for _ in range(self.N)]
            fx = self.Rq(f)
            if fx.is_unit():
                break

        g = [self.discrete_gaussian_sample(0, 1, 1) for _ in range(self.N)]
        gx = self.Rq(g)
        hx = gx / fx

        print(f)
        print(g)

        self.sk = (f, g)
        self.pk = hx

    def sign(self, m):
        hx = self.pk
        f, g = self.sk

        SHA = sha256()
        SHA.update(str(m).encode())
        Hm = bin(int.from_bytes(SHA.digest()))[2:].zfill(256)
        y1 = [self.discrete_gaussian_sample(0, 1, 2) for _ in range(self.N)]
        y2 = [self.discrete_gaussian_sample(0, 1, 2) for _ in range(self.N)]
        r = self.R([self.discrete_gaussian_sample((int(Hm[_] + Hm[(_ + 1) % 256],2) * self.qcg.next()) % 3 - 1, 1, 3) for _ in range(self.N)])

        w = hx * self.Rq(y1) + self.Rq(y2)
        SHA.update((str(hx) + str(w) + str(m)).encode())
        c = self.bytes2poly(SHA.digest())

        c = c.lift()

        z1 = c * self.R(y1) + r * self.R(f)
        z2 = c * self.R(y2) - r * self.R(g)

        print(self.R(y1), r)

        return z1, z2, c

    def bytes2poly(self, B):
        B = bin(int.from_bytes(B))[2:] * ceil(self.N // 256)
        return self.R([int(_) for _ in B])


    def discrete_gaussian_sample(self, center=0, sigma=1.0, bound=None):

        if sigma <= 0:
            raise ValueError("sigma error")

        if bound is None:
            bound = int(6 * sigma)

        candidates = list(range(int(center - bound), int(center + bound) + 1))

        weights = [exp(-((x - center) ** 2) / (2 * sigma**2)) for x in candidates]
        total = sum(weights)
        probs = [w / total for w in weights]

        return random.choices(candidates, weights=probs, k=1)[0]


def _handle_timeout(signum, frame):
    raise TimeoutError('function timeout')

timeout = 120
signal.signal(signal.SIGALRM, _handle_timeout)
signal.alarm(timeout)

FLAG = "flag{*************************************}"

print("""
                                                                                          
              ||||     |                                                                    
            |||||||   |||                                                                   
            ||   ||    ||                                                                   
           |||    |                                         |                               
           |||    |     |               |                  ||                               
            ||||       ||      |||     |||||||     |||     |||||              || ||    |||  
             |||||    |||     || |||| ||||  |||   |||||   |||||| ||| ||||    ||||||  ||   | 
               ||||    ||    ||   |||| ||    ||  ||  ||    ||     ||   ||   |||||||  |||||||
                 |||   ||    ||   ||   ||    ||  ||  ||    ||     ||   ||     ||    ||||||||
           ||     ||   ||    ||   ||   ||    ||    ||||    ||     ||   ||     ||    ||      
           ||     ||   ||    ||  ||    ||    ||   || ||    ||     ||   ||     ||    ||      
           |||    ||   ||     ||||     ||    ||  ||  ||    ||     ||   ||     ||    ||     |
           ||||||||    ||    ||       ||||  |||| || |||||  |||||  |||||||||   ||     |||||| 
            ||||||   |||||   |||||||  |||| ||||| |||||||   ||||    |||||||| ||||||   |||||  
                              |||||||                                                       
                            ||     ||                                                       
                            ||     ||                                                       
                            ||||||||                                                        
                              |||||                                                         

      """)



q = getPrime(256)
a, b, c = (random.randint(1, q - 1) for _ in range(3))
print("[+] a,b,c,q:",str([a, b, c, q]))

seed = int(input("[?] Give me a seed: "))
if 0 < seed < q:
    qcg = QCG(a, b, c, q, seed)


Sig = Signature(769, 256, qcg)
f,g = Sig.sk

print("[+] Now, let's start. I won't give you the public key because I know you can use it to do bad things!")

for _ in range(10001):
    m = input("[?] What message would you like to sign ?")
    z1, z2, c = Sig.sign(m)
    print("[+] z1 :", z1.list())
    print("[+] z2 :", z2.list())
    print("[+] c :", c.list())

_ = input("[?] 烫斤烫烫拷拷拷烫烫斤拷烫锟斤斤烫烫拷拷斤烫烫锟烫烫烫烫烫锟烫烫烫斤烫烫斤烫锟烫锟锟烫锟烫锟烫斤锟锟烫斤斤拷烫锟烫拷拷拷锟烫烫烫烫斤烫拷烫烫烫锟锟斤烫烫锟烫烫拷锟烫烫烫锟烫烫烫烫锟斤烫斤锟斤拷拷斤烫拷烫烫烫烫拷烫拷烫烫拷烫锟锟拷烫烫锟烫烫烫斤烫斤烫烫烫拷烫锟锟拷烫烫锟烫斤斤斤烫锟斤烫拷烫烫锟烫烫锟拷斤烫烫拷烫烫烫烫烫锟烫烫烫烫烫烫烫烫斤拷斤锟拷拷 ?")
print(_)
print(str(f + g))
import time
time.sleep(10)
if _ == str(f + g):
    print("[+] Win!", FLAG)
