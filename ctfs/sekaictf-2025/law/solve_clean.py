from sage.all import *
from pwn import *
from hashlib import sha256
from ast import literal_eval
from tqdm import tqdm
from py_ecc.secp256k1 import P, G as G_lib, N
from py_ecc.secp256k1.secp256k1 import multiply, add

context.log_level = 'debug'

NUM_PARTIES = 9
THRESHOLD = 7
p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

R = PolynomialRing(GF(p), ['x', 'y'])
xbar, ybar = R.gens()

def jacobian_double(p):
    """
    Double a point in Jacobian coordinates and return the result.

    :param p: the point to double
    :type p: PlainPoint3D

    :return: the resulting Jacobian point
    :rtype: PlainPoint3D
    """
    # if not p[1]:
    #     return (0, 0, 0)
    ysq = (p[1] ** 2)
    S = (4 * p[0] * ysq)
    A = 0
    M = (3 * p[0] ** 2 + A * p[2] ** 4)
    nx = (M**2 - 2 * S)
    ny = (M * (S - nx) - 8 * ysq**2)
    nz = (2 * p[1] * p[2])
    return (nx, ny, nz)

def send_point(p):
    io.sendline(str(p.point[0]).encode())
    io.sendline(str(p.point[1]).encode())

def send_int(n):
    io.sendline(str(n).encode())

def jacobian_add(p, q, return_H=False):
    """
    Add two points in Jacobian coordinates and return the result.

    :param p: the first point to add
    :type p: PlainPoint3D
    :param q: the second point to add
    :type q: PlainPoint3D

    :return: the resulting Jacobian point
    :rtype: PlainPoint3D
    """
    # if not p[1]:
    #     return q
    # if not q[1]:
    #     return p
    U1 = (p[0] * q[2] ** 2)
    U2 = (q[0] * p[2] ** 2)
    S1 = (p[1] * q[2] ** 3)
    S2 = (q[1] * p[2] ** 3)
    # if U1 == U2:
    #     if S1 != S2:
    #         return (0, 0, 1)
    #     return jacobian_double(p)
    H = U2 - U1
    R = S2 - S1
    H2 = (H * H)
    H3 = (H * H2)
    U1H2 = (U1 * H2)
    nx = (R**2 - H3 - 2 * U1H2)
    ny = (R * (U1H2 - nx) - S1 * H3)
    nz = (H * p[2] * q[2])
    if return_H:
        return (nx, ny, nz), H
    return (nx, ny, nz)

class Point:
    """easy operator overloading"""

    def __init__(self, x, y):
        self.point = (x, y)

    def __add__(self, other):
        return Point(*add(self.point, other.point))

    def __mul__(self, scalar):
        return Point(*multiply(self.point, scalar))

    def __rmul__(self, scalar):
        return Point(*multiply(self.point, scalar))

    def __neg__(self):
        return Point(self.point[0], -self.point[1])

    def __eq__(self, other):
        return (self + (-other)).point[0] == 0

    def to_jacobian(self):
        return (self.point[0], self.point[1], 1)

    def __repr__(self):
        return str(self.point)

G = Point(*G_lib)

def H(*args):
    return int.from_bytes(sha256(str(args).encode()).digest(), "big")

def verify_proof(C, R, mu, i):
    c = H(CONTEXT, i, C, R)
    return R == mu * G + (-c * C)

def sum_pts(points):
    res = 0 * G
    for point in points:
        res = res + point
    return res

def poly_eval_comms(comms, i):
    return sum_pts([comms[k] * pow(i, k, N) for k in range(THRESHOLD)])

def check_shares(comms, shares, i):
    return G * shares[i] == poly_eval_comms(comms, i)

def start():
    global CONTEXT, io
    # io = process(["python3", "chall.py"])
    io = remote('law-and-order.chals.sekai.team', 1337)
    io.recvuntil(b"context string")

    CONTEXT = bytes.fromhex(io.recvline().strip().decode())

    all_comms = {}

    for i in range(1, 9):
        io.recvuntil(b"[+] Commitments from party ")
        io.recvline()
        comm = []
        for j in range(THRESHOLD):
            c_j = literal_eval(io.recvline().strip().decode().split("=")[-1].strip())
            comm.append(Point(*c_j))
        all_comms[i] = comm

    pt0 = sum([all_comms[i][0] for i in range(1, NUM_PARTIES)], Point(0, 0))

    P0 = (0, ybar, 1)
    PA = jacobian_add(P0, pt0.to_jacobian())
    poly1 = PA[1]
    p3 = poly1.univariate_polynomial()

    def find():
        for y0 in p3.roots(multiplicities=False):
            if y0 == 0:
                continue
            your_comm0 = Point(0, int(y0))
            if (pt0 + your_comm0).point[1] != 0:
                continue
            return your_comm0

    your_comm0 = find()
    if your_comm0 is None:
        io.close()
        return

    assert (pt0 + your_comm0).point[1] == 0, (pt0 + your_comm0)
    assert (3 * your_comm0).point == (0, 0), (3 * your_comm0)

    def find_mu():
        for mu in range(1, 10000):
            R0 = mu * G
            if verify_proof(your_comm0, R0, mu, NUM_PARTIES):
                print(f"Found mu: {mu}")
                return R0, mu

    your_zero_proof = find_mu()
    your_comms = [your_comm0, Point(1, 0), Point(1, 0), Point(1, 0), Point(1, 0), Point(1, 0), Point(1, 0)]
    shares = [None, 0, 0, 0, 0, 0, 0, 0, 0, 0]

    for i in range(1, NUM_PARTIES + 1):
        print(i, check_shares(your_comms, shares, i))

    for your_comm in your_comms:
        send_point(your_comm)
    all_comms[NUM_PARTIES] = your_comms

    send_point(your_zero_proof[0])
    send_int(your_zero_proof[1])

    io.recvuntil(b"[+] Your commitments and proof have been accepted.")

    for i in range(1, NUM_PARTIES + 1):
        send_int(shares[i])

    my_shares = {}
    for i in range(1, NUM_PARTIES):
        io.recvuntil(b"[+] Share for you from party ")
        my_shares[i] = int(io.recvline().strip().decode().split(":")[-1].strip())
    my_shares[NUM_PARTIES] = 0

    target_point = sum_pts([poly_eval_comms(all_comms[j], NUM_PARTIES) for j in range(1, NUM_PARTIES + 1)])
    poly = 4 * ybar**2 - 3 * target_point.point[0] ** 3
    if len(poly.univariate_polynomial().roots(multiplicities=False)) == 0:
        print("No roots found for the polynomial, exiting.")
        io.close()
        return

    y_fake = poly.univariate_polynomial().roots(multiplicities=False)[0]
    P_fake = Point(target_point.point[0], y_fake)

    assert P_fake == target_point
    group_public_key = pt0 + your_comm0

    # send_point(P_fake)

    io.recvuntil(b"[+] Public verification shares have been computed.")

    def gen_D_E():
        while True:
            r = randint(1, p)
            E = Point(12*r**2 % p, 36*r**3 % p)
            D = (1337, ybar, 1)
            nonce = jacobian_add(D, E.to_jacobian())
            poly = nonce[1]
            poly = poly.univariate_polynomial()
            for y0 in poly.roots(multiplicities=False):
                if y0 == 0:
                    continue
                D = Point(1337, int(y0))
                nonsense_ordered = [(NUM_PARTIES, D, E)]
                m = "GIVE ME THE FLAG PLEASE"
                rho = H(NUM_PARTIES, m, nonsense_ordered)
                if rho % 3 == 1:
                    group_nonsense = D + E
                    group_challenge = H(group_nonsense, group_public_key, m)
                    if group_challenge % 3 != 0:
                        continue
                    return D, E
    
    D, E = gen_D_E()
    send_point(D)
    send_point(E)

    io.interactive()

    io.recvuntil(b"[+] Set of signers for this round: ")
    signers = literal_eval(io.recvline().strip().decode())
    print(f"Signers: {signers}")
    if len(signers) > 1:
        io.close()
        return

    io.recvuntil(b"[+] Group challenge `c`: ")
    c = int(io.recvline().strip().decode())
    print(f"Challenge {c}, {c % 3}")
    send_int(0)

    io.interactive()

for _ in range(100):
    start()
