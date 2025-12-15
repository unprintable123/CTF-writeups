from sage.all import *

p = 2**130 - 5

r = randint(1,p-1)

eqs = []
for _ in range(64):
    xi = randint(1, 2**120)
    ti = (xi * r**2) % p
    ei = (ti // 2 ** 128) -2
    eqs.append((xi, ei, ti - ei * 2 ** 128))

xs, es, ts = zip(*eqs)

vx = vector(ZZ, list(xs))
ve = vector(ZZ, list(es))
vt = vector(ZZ, list(ts))

M = block_matrix(ZZ, [[p*identity_matrix(1)*100, matrix([vt])*100], [0, identity_matrix(len(ts))]]).T
M = M.LLL(algorithm='flatter')
M = M.BKZ(block_size=24)

M = M[:40, 1:]
print(M*ve)
print(M.right_kernel().matrix().LLL(algorithm='flatter')[0])
print(ve)
