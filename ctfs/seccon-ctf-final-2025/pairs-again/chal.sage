# https://gist.github.com/maple3142/8933b70e6011043b65849314563fba55

# BLS12-381
# https://hackmd.io/@benjaminion/bls12-381
x = var("x")
q = 0x1A0111EA397FE69A4B1BA7B6434BACD764774B84F38512BF6730D2A0F6B0F6241EABFFFEB153FFFFB9FEFFFFFFFFAAAB
r = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001
Fq = GF(q)
Fq2 = GF(q ^ 2, "i", x ^ 2 + 1)
i = Fq2.gen()
u6 = 1 / (1 + i)
b = 4


E1 = EllipticCurve(Fq, (0, b))
E2 = EllipticCurve(Fq2, (0, b / u6))
G1 = E1.lift_x(
    3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507
)
G2 = E2.lift_x(
    352701069587466618187139116011060144890029952792775240219908644239793785735715026873347600343865175952761926303160
    + i
    * 3059144344244213709971259814753781636986470325476647558659373206291635324768958432433509563104347017837885763365758
)
assert r * G1 == 0
assert r * G2 == 0


u, i = polygens(Fq, "u,i")
mod = ((1 + i) * u ^ 6 - 1).sylvester_matrix(i ^ 2 + 1, i).det().univariate_polynomial()
Fq12 = GF(q ^ 12, "u", mod)
u = Fq12.gen()
E3 = EllipticCurve(Fq12, [0, 4])
i_in_fq12 = Fq2.modulus().change_ring(ZZ)(polygen(Fq12)).roots(multiplicities=False)[1]
assert i_in_fq12**2 + 1 == 0


def fp2_to_fq12(el):
    return el.polynomial()(i_in_fq12)


G1x = E3(G1)
G2x = E3(u ^ 2 * fp2_to_fq12(G2[0]), u ^ 3 * fp2_to_fq12(G2[1]))
assert r * G1x == 0
assert r * G2x == 0

# ------------------------------

import ast
import signal

with open("flag.txt", "r") as f:
    FLAG = f.read()

def pairing(P, Q):
    return (P._miller_(Q, 1337 * r)) ^ ((q ^ 12 - 1) // r)

signal.alarm(30)

Px = int(input("Px: "))
Py = int(input("Py: "))
P = E3(Fq(Px), Fq(Py))
Q = randrange(1, r) * G2x
t = pairing(P, Q)
assert t != 1
print("pairing(P, Q) =", t)

Qx = Fq12(ast.literal_eval(input("guess Qx: ")))
Qy = Fq12(ast.literal_eval(input("guess Qy: ")))
Q_ = E3(Qx, Qy)

if t == pairing(P, Q_):
    print(FLAG)
