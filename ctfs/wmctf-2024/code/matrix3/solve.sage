p = 2**302 + 307
k = 140
n = 10
alpha = 3
GFp = GF(p)

Dlist = load("Dlist2.sobj")

def flatter(M):
    from subprocess import check_output
    from re import findall
    z = "[[" + "]\n[".join(" ".join(map(str, row)) for row in M) + "]]"
    ret = check_output(["flatter"], input=z.encode())
    return matrix(M.nrows(), M.ncols(), map(int, findall(b"-?\\d+", ret)))

def flatten_matrix(F, M):
    c = []
    for v in M:
        for x in v:
            c.append(F(x))
    return c

def one_hot(i, n):
    ret = [0]*n
    ret[i] = 1
    return vector(GFp, ret)

def gen_sign(one_line):
    a = one_line[0]
    b = one_line[1]
    c = one_line[2]
    a0 = a/b
    b0 = b/c
    return ZZ(a0) + ZZ(b0)*p

# D = load("Dlist2.sobj")
# D_ = []
# for _ in range(140):
#     D_.append(D[_].list())

# D_ = matrix(D_).change_ring(ZZ)

# g = 2^512
# A = matrix(ZZ, 140+100, 140+100)
# A[:140,:140] = identity_matrix(140)
# A[:140,140:] = D_*g
# A[140:,140:] = identity_matrix(100)*p*g

# AL = flatter(A)[:40].T
# # AL = A.LLL()
# print("LLL1 done")

# B = matrix(ZZ, 180, 180)
# B[:140,:140] = identity_matrix(140)
# B[:140,140:] = AL[:140]*g
# B[140:,140:] = identity_matrix(40)*p*g

# BL = flatter(B)
# print("LLL2 done")

# LA_ = list((BL[:100].T)[:140].T)
# LA_.append([-1]*140)
# LA = matrix(ZZ, LA_)

# LB = matrix(ZZ, 101, 1+140)
# LB[100,0] = 2
# LB[:,1:] = LA

# svec = LB.BKZ(block_size=40)
# one_vec = vector(ZZ, [1]*140)

# cal = svec[0][0]/2*svec[0][1:]+one_vec
# def check(i):
#     return all([_ in [0,1,2] for _ in i])

# s = []
# for v in svec:
#     if v[0] == -2:
#         assert check(-v[1:]+one_vec)
#         s.append(-v[1:]+one_vec)
#     else:
#         assert check(v[1:]+one_vec)
#         s.append(v[1:]+one_vec)
# print(len(s))
# s.remove(vector([0]*140))
# S = matrix(GFp, s)


# signs = []
# Rs = []
# for t in range(100):
#     v = S.solve_right(one_hot(t, 100))
#     TMP = zero_matrix(GFp, 10, 10)
#     for i in range(140):
#         TMP += Dlist[i] * v[i]
#     assert gen_sign(TMP[0]) == gen_sign(TMP[1])
#     Rs.append(TMP)
#     signs.append((gen_sign((TMP.T)[0]), gen_sign(TMP[0])))

# rows, cols = zip(*signs)
# rows = list(set(rows))
# cols = list(set(cols))
# assert len(rows) == 10
# assert len(cols) == 10

# E_cols = []
# E_inv_rows = []
# for i in range(100):
#     a, b = signs[i]
#     if a == rows[0]:
#         E_inv_rows.append(Rs[i][0])
#     if b == cols[0]:
#         E_cols.append((Rs[i].T)[0])

# E = matrix(GFp, E_cols).T
# E_inv = matrix(GFp, E_inv_rows)

# real_E = load("E.sobj")
# save(E, "fake_E.sobj")
# save(E_inv, "fake_E_inv.sobj")

E = load("fake_E.sobj")
E_inv = load("fake_E_inv.sobj")
# print(gen_sign((real_E.T)[0]))
# for v in E.T:
#     for i in range(10):
#         if gen_sign(v) == gen_sign((real_E.T)[i]):
#             print((real_E.T)[i][0]/v[0])

# real_E_inv = real_E**-1

# for v in E_inv:
#     for i in range(10):
#         if gen_sign(v) == gen_sign(real_E_inv[i]):
#             print(real_E_inv[i][0]/v[0])

ad = max((E_inv*E).change_ring(ZZ).list())
E /= ad
E = E_inv**(-1)

if E*E_inv == identity_matrix(10):
    print(E)
    print(E_inv*Dlist[0]*E)

from pwn import *
import time
context.log_level = "debug"
io = remote("8.147.134.27", 34410)
for v in E:
    io.sendline(" ".join(hex(ZZ(x))[2:] for x in v))
    time.sleep(1)
io.interactive()

# M0 = [flatten_matrix(ZZ, Dlist[i]) for i in range(k)]
# # M0.append(flatten_matrix(ZZ, identity_matrix(n)))
# M0 = matrix(ZZ, M0)
# M = block_matrix(ZZ, [[identity_matrix(140), M0], [zero_matrix(ZZ, 100, 140), identity_matrix(100)*p]])
# for i in range(140, 240):
#     M.rescale_col(i, 2048)

# # M = flatter(M)
# # save(M, "M.sobj")

# M = load("M.sobj")

# M = M[:40, :140].T

# M2 = block_matrix(ZZ, [[identity_matrix(140), M*2048]])
# M2 = flatter(M2)

# LA_ = list(M2[:100, :140])
# LA_.append([-1]*140)
# LA = matrix(ZZ, LA_)
# LB = matrix(ZZ, 101, 1+140)
# LB[100,0] = 2
# LB[:,1:] = LA
# LB = flatter(LB)
# print(LB)
