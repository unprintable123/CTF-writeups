from sage.all import *
import base64

F = Qp(2, 80)

def get_roots(y, u2, u1, u0):
    y = F(y)
    u2 = F(u2)
    u1 = F(u1)
    u0 = F(u0)
    y = y / u2
    u1 = u1 / u2
    u0 = u0 / u2
    # y = x*(x + u1) + u0
    delta = u1**2 + 4 * (y - u0)
    r0 = delta.nth_root(2)
    r0 = ZZ(r0)
    r1 = r0 * (2**47+1)
    r2 = r0 * (2**47-1)
    r3 = -r0
    def solve_x(r):
        b =  (r - ZZ(u1)) % (2**48)
        assert b % 2 == 0
        return [b // 2, (b // 2 + 2**47) % (2**48)]
    return solve_x(r0) + solve_x(r1) + solve_x(r2) + solve_x(r3)

def to_poly(input):
    poly = 0
    for i in range(48):
        if (input >> (47-i)) & 1:
            poly += x**i
    return poly

def byte_to_poly(input):
    poly = 0
    for i in range(8):
        if (input >> (7-i)) & 1:
            poly += x**i
    return poly

def post(data):
    import requests
    res = requests.post("http://202.38.93.141:19975/answer_c.py", data=data)
    # print(res.text)
    return res.json()

x = 101015717
# u2 = 241818181881667
# u1 = 279270832074457
# u0 = 202208575380941
# u2, u1, u0 = (223539323800223, 186774198532003, 106397893833919)
print(base64.b85decode(b"answer_c"))
u2, u1, u0 = (246290604621823, 281474976710655, 281474976710655)  
y = (x*(x*u2 + u1) + u0) % (2**48)
rl0 = get_roots(int.from_bytes(bytes.fromhex("a5a1b43c4399"), "little"), u2, u1, u0)
rl1 = get_roots(int.from_bytes(bytes.fromhex("bb7ba6d4a331"), "little"), u2, u1, u0)
rl2 = get_roots(int.from_bytes(bytes.fromhex("39bb0977c7d9"), "little"), u2, u1, u0)
rl = get_roots(int.from_bytes(base64.b85decode(b"answer_c"), "little"), u2, u1, u0)
print([hex(x) for x in rl1])

F2 = GF(2)
R = PolynomialRing(F2, "x")
x = R.gen()

c = sum([x**i for i in range(48)])



poly_txt = 'CcccCCcCcccCCCCcCCccCCccccCccCcCCCcCCCCCCCccCCCCC'
flip = sum(['c', 'C'].index(poly_txt[i + 1]) << i for i in range(48))  
mod_p = to_poly(flip) + x**48
print(mod_p)

p0 = c * (x**8) - c + byte_to_poly(ord("0")) * (x**48)
p1 = c * (x**8) - c + byte_to_poly(ord("1")) * (x**48)
p2 = c * (x**8) - c + byte_to_poly(ord("2")) * (x**48)

# print(p1)

# print(p1.quo_rem(mod_p))

# print(to_poly(204341017745755))

for r0 in rl0:
    for r1 in rl1:
        for r2 in rl2:
            poly0 = p0 - to_poly(r0)
            poly1 = p1 - to_poly(r1)
            poly2 = p2 - to_poly(r2)
            mod_p_guess = gcd(poly1, poly2)
            mod_p_guess = gcd(mod_p_guess, poly0)
            if mod_p_guess.degree() > 24:
                # print(mod_p_guess)
                base_chr = ord("c")
                b = []
                cl = mod_p_guess.list()
                for i in range(49):
                    if cl[i] == 1:
                        b.append(base_chr ^ 32)
                    else:
                        b.append(base_chr)
                # print(bytes(reversed(b)))



def forge_data(input, forge_range = (0, 56)):
    input = bytearray(input)
    l = len(input)
    base = c * (x**(8*l)) - c
    for i in range(l):
        base += byte_to_poly(input[i]) * (x**(8*(l-1-i)+48))
    base = base.quo_rem(mod_p)[1]
    forge_target = to_poly(rl[0])
    basis = []
    id_list = []
    for i in range(forge_range[0], forge_range[1]):
        if i % 8 == 7:
            continue
        poly = x ** (48+8*l-1-i)
        poly = poly.quo_rem(mod_p)[1] + mod_p
        basis.append(poly)
        id_list.append(i)
    M = matrix(F2, [p.list() for p in basis]+[mod_p.list()])
    print(M.rank())
    target_v = vector((forge_target - base + mod_p).list())
    sol_v = M.solve_left(target_v)
    for i in range(len(id_list)):
        if sol_v[i] == 1:
            input[id_list[i] // 8] ^= 1 << (id_list[i] % 8)
    # print(bytes(input))
    return bytes(input)

suffix = b"6Gc8##buBY?WpXW4axrCOEmSZqM|EX$b1g7#Wi2pfEmUY_EmAOdb3c6"
for _ in range(56):
    print(suffix)
    dlist = [forge_data(b"\x80"*(63-len(suffix))+bytes([i])+suffix) for i in range(32, 128)]
    # print(dlist)
    ret = post(b"\n".join(dlist))["wrong_hints"]
    for line in ret:
        if ret[line].startswith("Too few lines"):
            continue
        assert ret[line].startswith("Unmatched data "), ret[line]
        bad_byte = int(ret[line].split("(")[1][:-1], 16)
        if bad_byte == 128:
            suffix = bytes([31+int(line)]) + suffix
