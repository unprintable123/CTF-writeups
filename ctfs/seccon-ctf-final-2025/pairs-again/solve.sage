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

from pwn import *
context.log_level = "debug"

P = E1.torsion_basis(11)[0]
P = E3(P)

def pairing(P, Q):
    return (P._miller_(Q, 1337 * r)) ^ ((q ^ 12 - 1) // r)

def compute_f(n):
    if n == 1:
        return 1
    t = compute_f(n-1)
    return t * get_g(n-1, 1)

# 定义多项式环，x 和 y 是变量
R.<x, y> = PolynomialRing(Fq12, 2, order='invlex')

def get_line_function(A, B):
    """
    计算经过点 A 和 B 的直线函数 L_{A,B}(x, y)
    E: y^2 = x^3 + a*x + b
    """
    E = A.curve()
    
    # 处理无穷远点 O
    if A.is_zero() or B.is_zero():
        return R(1) # 通常在配对算法中，涉及 O 的直线定义为常数
    
    x1, y1 = A.xy()
    x2, y2 = B.xy()
    
    # 情况 1: A == B (切线)
    if A == B:
        # 如果 y1 == 0，切线是铅垂线 x - x1
        if y1 == 0:
            return x - x1
        # 计算斜率 lambda = (3*x1^2 + a) / (2*y1)
        lmbda = (3*x1^2 + E.a4()) / (2*y1)
        return y - y1 - lmbda * (x - x1)
    
    # 情况 2: A == -B (铅垂线)
    elif x1 == x2:
        return x - x1
    
    # 情况 3: A != B (割线)
    else:
        # 计算斜率 lambda = (y2 - y1) / (x2 - x1)
        lmbda = (y2 - y1) / (x2 - x1)
        return y - y1 - lmbda * (x - x1)

def get_g_poly(i, j):
    A = i * P
    B = j * P
    C = (i + j) * P
    return get_line_function(A, B) / get_line_function(-C, C)

def compute_f_poly(n):
    if n == 1:
        return 1
    t = compute_f_poly(n-1)
    u = t * get_g_poly(n-1, 1)
    r1 = u.numerator()
    r2 = u.denominator()
    r1 = r1.reduce([x^3 + 4 - y^2])
    r2 = r2.reduce([x^3 + 4 - y^2])
    return r1 / r2
    # return u

poly6 = compute_f_poly(6)
poly11 = compute_f_poly(11)

def solve(ratio):
    # solve poly6 ** 11 == ratio * poly11 ** 6
    poly6_a = poly6.numerator()
    poly6_b = poly6.denominator()
    poly11_a = poly11.numerator()
    poly11_b = poly11.denominator()
    eq = poly6_a ** 11 * poly11_b ** 6 - ratio * poly6_b ** 11 * poly11_a ** 6
    eq = eq.reduce([x^3 + 4 - y^2])
    eq = eq * eq(y=-y)
    eq = eq.reduce([x^3 + 4 - y^2])
    eq = eq.univariate_polynomial()
    for r in eq.roots(multiplicities=False):
        Q = E3.lift_x(r)
        x0, y0 = Q.xy()
        f6 = poly6(x=x0, y=y0)
        f11 = poly11(x=x0, y=y0)
        if f6 ** 11 == ratio * f11 ** 6:
            print("Found Q:", Q)
            return Q

for _ in range(4):
    try:
        io = process(['sage', 'chal.sage'])
        io.recvuntil(b"Px:")
        io.sendline(str(P.x()).encode())
        io.recvuntil(b"Py:")
        io.sendline(str(P.y()).encode())
        io.recvuntil(b"pairing(P, Q) = ")
        t=sage_eval(io.recvline().decode(), locals={"u":u})
        print(t)
        t1 = t ** 11
        pp = (q ^ 12 - 1) // r
        t0 = t1 ** (pow(pp, -1, r))
        assert t0 ** pp == t1

        g = pow(65537, r, q)
        for i in range(3):
            try:
                Q2 = solve(t0 * g ** i)
                continue
            except:
                pass
        # print(pairing(P, Q2))
        assert pairing(P, Q2) == t

        io.recvuntil(b"guess Qx:")
        io.sendline(str(Q2.x().list()).encode())
        io.recvuntil(b"guess Qy:")
        io.sendline(str(Q2.y().list()).encode())
        io.interactive()
    except:
        io.close()
