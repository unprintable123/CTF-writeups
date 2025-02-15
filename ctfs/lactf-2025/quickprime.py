#!/usr/local/bin/python3

from secrets import randbits
from Crypto.Util.number import isPrime
from sage.all import *


class LCG:

    def __init__(self, a: int, c: int, m: int, seed: int):
        self.a = a
        self.c = c
        self.m = m
        self.state = seed

    def next(self):
        self.state = (self.a * self.state + self.c) % self.m
        return self.state


while True:
    a = randbits(512)
    c = randbits(512)
    m = 1 << 512
    seed = randbits(512)
    initial_iters = randbits(16)
    # https://en.wikipedia.org/wiki/Linear_congruential_generator#m_a_power_of_2,_c_%E2%89%A0_0
    if (c != 0 and c % 2 == 1) and (a % 4 == 1):
        print(f"LCG coefficients:\na={a}\nc={c}\nm={m}")
        break

L = LCG(a, c, m, seed)
for i in range(initial_iters):
    L.next()

P = []
while len(P) < 2:
    test = L.next()
    if isPrime(test):
        P.append(test)

p, q = P

n = p * q

# t = (p - 1) * (q - 1)

# e = 65537

# d = pow(e, -1, t)

# message = int.from_bytes(open("flag.txt", "rb").read(), "big")

# ct = pow(message, e, n)

# print(f"n={n}")
# print(f"ct={ct}")

a=8346937052786646660185429090271475802481647625422813411292121724588502880437118703200550776532467386135762524368991640855910091869726402493649109146727353
c=12562706502279443777284313987673626274827293425553536602753035080077194320830621710023848795067075764241974074631331210284053430984609472108081760402087109
m=13407807929942597099574024998205846127479365820592393377723561443721764030073546976801874298166903427690031858186486050853753882811946569946433649006084096
n=15609423701713706929637300214258354828165587256573324444535587255892833032883307340268787926995852322664267249190576826410217590480090816667777971077024637964639056237496866192731294964060368225860925068173057948940881072279192698129406090801089230062074428508290287184000152170968295305026279679310740744577
ct=15331747250977537513530616999975126553418981390761490063181982221005313033243976596662158664483924559080624005159825396497660126295050613516906556998884413626475982765818872560161446299907685137378294423499714176856031229494518668454512553899549297720260300698921272374676034759015514436264975756584293953317

def try_solve(ai,ci,n):
    # x*(ai*x+ci) = n mod m
    d = mod(ci,m) / mod(ai,m)
    # x*(x+d) = n/ai mod m
    s = 4*mod(n,m)/ai + d**2
    # (2x+d)^2 = s mod m
    if not s.is_square():
        return []
    r = s.nth_root(2)
    if ZZ(r-d)%2 != 0:
        return []
    xs = []
    x0 = ZZ(r-d)//2
    x1 = ZZ(-r-d)//2
    for i in range(4):
        xs.append(x0+i*2**510)
        xs.append(x1+i*2**510)
    return xs


a0 = a
c0 = c
for _ in range(10000):
    xs = try_solve(a0,c0,n)
    for x in xs:
        x = int(x % 2**512)
        for j in range(10):
            xx = x + j*2**512
            if n % xx == 0:
                print("Found factor", xx)
                break
    
    a0 = a0 * a % m
    c0 = (c0 * a + c) % m

p = 2848838946355199739311600186698819851932938274173580869655979392137097271653921227002619674609410205998728484081571921867338750235774164148307765888275479
q = n // p
assert p*q == n

t = (p - 1) * (q - 1)
e = 65537
d = pow(e, -1, t)

m = pow(ct, d, n)
print(m.to_bytes((m.bit_length() + 7) // 8, "big"))






