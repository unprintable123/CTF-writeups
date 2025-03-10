import os
from polynomial import fast_polynomial_gcd
from mul import fast_MV_Element, fast_MV_Ring
from random import shuffle
from functools import lru_cache
from hashlib import sha256
from Crypto.Random import random as cryrand

def flatter(M):
    from subprocess import check_output
    from re import findall
    z = "[[" + "]\n[".join(" ".join(map(str, row)) for row in M) + "]]"
    ret = check_output(["flatter"], input=z.encode())
    return matrix(M.nrows(), M.ncols(), map(int, findall(b"-?\\d+", ret)))

with open("output.txt", "r") as f:
    p, a, b = map(int, f.readline().strip().split())
    p = ZZ(int(p))
    EC = EllipticCurve(GF(p), [a, b])

def reduce_mod(f, mods):
    for (y, rem) in mods:
        u = f.quo_rem(y**2)

def jacobian_double(P, Ideal=None):
    ua = EC.a4()
    uX1, uY1, uZ1 = P
    uXX = ((uX1^2))
    uYY = ((uY1^2))
    uZZ = ((uZ1^2))
    if Ideal is not None:
        uX1 = uX1.reduce(Ideal)
        uY1 = uY1.reduce(Ideal)
        uZ1 = uZ1.reduce(Ideal)
    uS = (((uX1*4)*uYY))
    uM = ((uXX*3+ua*uZZ^2))
    if Ideal is not None:
        uS = uS.reduce(Ideal)
        uM = uM.reduce(Ideal)
    uT = ((uM^2-(2)*uS))
    if Ideal is not None:
        uT = uT.reduce(Ideal)
    uX3 = ((uT))
    uY3 = ((uM*(uS-uT)-(8)*uYY^2))
    uZ3 = (((2)*uY1*uZ1))
    if Ideal is not None:
        uX3 = uX3.reduce(Ideal)
        uY3 = uY3.reduce(Ideal)
        uZ3 = uZ3.reduce(Ideal)
    return (uX3, uY3, uZ3)

def jacobian_add(P, Q, Ideal=None):
    print("add", P[0].degree(), Q[0].degree())
    X1, Y1, Z1 = P
    X2, Y2, Z2 = Q
    Z1Z1 = Z1**2
    Z2Z2 = Z2**2
    if Ideal is not None:
        Z1Z1 = Z1Z1.reduce(Ideal)
        Z2Z2 = Z2Z2.reduce(Ideal)
    U1 = X1*Z2Z2
    U2 = X2*Z1Z1
    S1 = Y1*Z2*Z2Z2
    S2 = Y2*Z1*Z1Z1
    if Ideal is not None:
        S1 = S1.reduce(Ideal)
        S2 = S2.reduce(Ideal)
    H = U2-U1
    I = (H*2)**2
    if Ideal is not None:
        I = I.reduce(Ideal)
    J = H*I
    r = (S2-S1)*2
    V = U1*I
    if Ideal is not None:
        J = J.reduce(Ideal)
        r = r.reduce(Ideal)
        V = V.reduce(Ideal)
    X3 = r**2-J-V*2
    if Ideal is not None:
        X3 = X3.reduce(Ideal)
    Y3 = r*(V-X3)-S1*J*2
    Z3 = ((Z1+Z2)**2-Z1Z1-Z2Z2)*H
    if Ideal is not None:
        X3 = X3.reduce(Ideal)
        Y3 = Y3.reduce(Ideal)
        Z3 = Z3.reduce(Ideal)
    return (X3, Y3, Z3)

def point_gcd(P):
    I = R.ideal([ys[0]-1])
    f0 = P[0]
    if "y" in str(f0.variables()):
        f0 = f0.reduce(I)
    f1 = P[1]
    if "y" in str(f1.variables()):
        f1 = f1.reduce(I)
    f2 = P[2]
    if "y" in str(f2.variables()):
        f2 = f2.reduce(I)
    f0 = R0(f0)
    f1 = R0(f1)
    f2 = R0(f2)
    return fast_polynomial_gcd(fast_polynomial_gcd(f0, f1), f2)

def recude_gcd(P):
    g = point_gcd(P)
    if g.degree() > 0:
        return (P[0]//g**2, P[1]//g**3, P[2]//g)
    return P

def jacobian_mul(P, n, I=None):
    # ladder algorithm
    R0 = P
    R1 = jacobian_double(P, Ideal=I)
    for bit in bin(n)[3:]:
        # print("debug:", bit, R0[0].degree())
        if bit == "0":
            R1 = jacobian_add(R0, R1, Ideal=I)
            R0 = jacobian_double(R0, Ideal=I)
        else:
            R0 = jacobian_add(R0, R1, Ideal=I)
            R1 = jacobian_double(R1, Ideal=I)
        R0 = recude_gcd(R0)
        R1 = recude_gcd(R1)
        
    return R0

a, b = EC.a4(), EC.a6()
R = PolynomialRing(GF(p), ['r', 'y0'], order='invlex')

r = R.gen(0)
ys = R.gens()[1:]
R0 = PolynomialRing(GF(p), ['r'], order='invlex')


I0 = R.ideal([ys[0]**2-(r**3+a*r+b)])
mul_caches = {}
def get_mul(n):
    if n in mul_caches:
        return mul_caches[n]
    def _get_mul(n):
        if n == 1:
            return (r, ys[0], R(1))
        if n % 2 == 0:
            return recude_gcd(jacobian_double(get_mul(n//2), I0))
        else:
            P1 = get_mul(n//2)
            P2 = get_mul(n//2+1)
            return recude_gcd(jacobian_add(P1, P2, I0))
    ret = _get_mul(n)
    mul_caches[n] = ret
    return ret

def get_mul_r(r0, n):
    P0 = get_mul(n)
    a, b = EC.a4(), EC.a6()
    y0 = ys[0]
    return tuple(map(lambda f: f(r=r0).quo_rem(y0), P0)), (r0**3+a*r0+b)



fake_r = cryrand.randrange(int(p))
# fake_r = 0
order = EC.cardinality()
# print(order)

K = EC.gens()[0] * cryrand.randrange(int(order))
samples = []
sss = 0
for i in range(6):
    a = cryrand.randrange(int(order))
    b = cryrand.randrange(int(12))+1
    out = (a * K).x() + fake_r
    sss += a * b
    samples.append((a, out, b))
out = (-sss * K).x() + fake_r
samples.append((-sss, out, 1))

# samples = [(-423281967758517149649799, 936819061794862502069005, 1), (-474577412660795835011498, 329320086155386260162697, 8), (957829019411417181524004, 474501436219948796198731, 13), (272732186398662199750753, 774709326620779317733256, 8), (911331833265365909333225, 408175900791791960877267, 2), (359934589527781974638451, 960844040767122432002391, 6), (-145681471797145280626117, 120936724925527394274222, 2), (-51506965646018738836124, 11703089032114655636391, 12), (-40376470118773205428771, 1184922264315527863957356, 27), (1147498768111382654856539, 877912653845988493749677, 5)]
# samples = [(900500237901720754956300, 451333156197236767458849, 9), (480332738470663933330989, 246252309767325542574057, 6), (-597647977327231955213683, 106554575621443028118987, 31), (354179151074954899629288, 1002404228729063773654729, 14), (166538786702093118014455, 80968502532589232148280, 2), (-38749959342352129836770, 946878433156363205059109, 5), (860500656504563516678680, 854302189687926940564400, 18), (620208224314140003467840, 731263854545207654441397, 16)]
# samples = [(-917775730121413171720261, 98338073380592890325046, 18), (-226108667839250255625786, 324225003603776834226237, 21), (-1129327372794372384936075, 940964235523053332891666, 20), (701392897944894705336387, 1134348227428711301423813, 15), (-204614234224945423678176, 962616304002348990735367, 10), (860669053807675365899255, 258824071356015434469912, 11), (916986820978713770939182, 326687021271580507310175, 3), (1015184196476017012559785, 438096491867752661635783, 22), (-399872620051218174065669, 970336337134644860482989, 7)]


assert sum(a*b for a, _, b in samples) % order == 0



work_dir = f"outputs/{sha256(str(samples).encode()).hexdigest()[:32]}"
os.makedirs(work_dir, exist_ok=True)
with open(work_dir + "/samples.txt", "w") as f:
    f.write(str(samples))


Ps, polys = zip(*[get_mul_r(out-r, b) for i, (a, out, b) in enumerate(samples)])

polys = [R0(p) for p in polys]

RR = fast_MV_Ring(polys)

def to_RR(quorem, idx):
    return RR.yval(idx) * RR.uni_poly(quorem[0]) + RR.uni_poly(quorem[1])

Ps = [tuple(map(lambda x: to_RR(x, i), P)) for i, P in enumerate(Ps)]

save(Ps, work_dir + "/Ps.sobj")
flag = False

while len(Ps) > 2:
    Ps = sorted(Ps, key=lambda x: x[2].degree())
    print([P[2].degree() for P in Ps])
    if flag:
        P0 = Ps.pop(2)
        flag = False
    else:
        P0 = Ps.pop(0)
    P1 = Ps.pop(0)
    Ps.append(jacobian_add(P0, P1))

save(Ps, work_dir + "/Ps2.sobj")

print([P[2].degree() for P in Ps])

P1, P2 = Ps
P1P1 = (P1[2]**2)
P2P2 = (P2[2]**2)
f = P1[0]*P2P2 - P2[0]*P1P1
save(f, work_dir + "/f0.sobj")
print(f.degree())

assert len(polys) == len(samples)

for i in range(len(samples)):
    if f.has_yval(i):
        f = f.flip(i)*f
        
        save(f, work_dir + f"/f{i+1}.sobj")
        print(f.degree())

f = f.coeffs[0]
save(f, work_dir + "/final.sobj")
print(f(r=ZZ(fake_r)))


