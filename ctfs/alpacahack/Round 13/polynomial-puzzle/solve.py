from sage.all import *
from pwn import *
from ast import literal_eval

context.log_level = 'debug'

d = 20

# io = process(['sage', 'chall.sage'])
# nc 34.170.146.252 32292
io = remote('34.170.146.252', 32292)
io.recvuntil(b'Finite Field of size ')

P = int(io.recvline().strip().decode())
K = GF(P)
R = PolynomialRing(K, 'x')
x = R.gen()
print(f"Field size: {P}")

pairs = []
for _ in range(d + 3):
    io.recvuntil(b'f(')
    x0 = int(io.recvuntil(b')').strip(b')').decode())
    io.recvuntil(b'values of ')
    vals = literal_eval(io.recvline().strip().decode())

    pairs.append((x0, vals))

xs = [x for x, _ in pairs]
polys = []

for i in range(len(pairs)):
    p = 1
    for j in range(len(pairs)):
        if i != j:
            p *= (x - xs[j]) / (xs[i] - xs[j])
    polys.append(p)
    assert p(x=xs[i]) == 1

def make_vals(vals, p0):
    for i, j in [(0, 1), (0, 2), (1, 2), (0, 3), (1, 3), (2, 3)]:
        v = vals[i] + vals[j]
        yield (v * p0).list()[-2:]

solver = process(['./mitm'], shell=True)
solver.sendline(str(P).encode())
for i in range(23):
    x0, vals = pairs[i]
    p0 = polys[i]
    all_vals = list(make_vals(vals, p0))
    for v in all_vals:
        solver.sendline(f"{v[0]} {v[1]}".encode())

solver.recvuntil(b'Found matching sum: ')
inds = list(map(int, solver.recvline().strip().decode().split()))
solver.close()

def split_index(index, n):
    # 3 bit
    inds = []
    for i in range(n):
        inds.append(index % 8)
        index //= 8
    return inds[::-1]

inds = split_index(inds[0], 6) + split_index(inds[1], 6) + split_index(inds[2], 11)

print(inds)
poly0 = 0
for i in range(23):
    x0, vals = pairs[i]
    p0 = polys[i]
    a, b = [(0, 1), (0, 2), (1, 2), (0, 3), (1, 3), (2, 3)][inds[i]]
    poly0 += (vals[a] + vals[b]) * p0
print(poly0)

io.sendline(str(poly0(x=42)).encode())
io.interactive()

# Alpaca{Sorry_for_BKZ_requiring_params_but_I_had_to_block_the_naive_solution_>:)}
