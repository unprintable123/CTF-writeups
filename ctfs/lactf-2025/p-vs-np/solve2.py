from sage.all import *
from pwn import *
from VDF import r_value, verify_proof

# io = process(['python3', 'chall.py'])
# nc chall.lac.tf 31182
io = remote('chall.lac.tf', 31182)

io.recvuntil(b'g = ')
g = int(io.recvline().decode().strip())
print(g)
y = 2
io.sendline(str(y).encode())
io.recvuntil(b'N = ')
N = int(io.recvline().decode().strip())
print(N)
fac = ZZ(N).factor(algorithm='qsieve')
p = int(fac[0][0])
q = int(fac[1][0])
assert p*q == N
print(p, q)
d = int(lcm(p-1, q-1))

logT = 70
e = pow(2, 2**logT, d)

pi_s = []

for i in range(2**19):
    mu_i = i+10
    if gcd(mu_i, N) != 1:
        continue
    if i % 2**16 == 0:
        print(hex(i))
    r_i = r_value(g, y, mu_i) % N
    xi = (pow(g, r_i, N) * mu_i) % N
    yi = (pow(mu_i, r_i, N) * y) % N
    if (yi % p) == pow(xi, e, p):
        print(i)
        pi_s.append(mu_i)
        break

print(xi, yi)
assert yi % p == pow(xi, e, p)

e2 = pow(2, 2**(logT-1), d)
assert e2**2 % d == e
mu_i_p = pow(xi, e2, p)
assert pow(mu_i_p, e2, p) == yi % p

for i in range(q):
    mu_i = mu_i_p + i*p
    if gcd(mu_i, N) != 1:
        continue
    if i % 2**16 == 0:
        print(hex(i))
    r_i = r_value(xi, yi, mu_i) % N
    xi2 = (pow(xi, r_i, N) * mu_i) % N
    yi2 = (pow(mu_i, r_i, N) * yi) % N
    # assert yi2 % p == pow(xi2, e2, p)
    if (yi2 % N) == pow(xi2, e2, N):
        print(i, mu_i)
        pi_s.append(mu_i)
        break

assert yi2 % N == pow(xi2, e2, N)

for j in reversed(range(logT-1)):
    e = pow(2, 2**j, d)
    mu_i = pow(xi2, e, N)
    ri = r_value(xi2, yi2, mu_i) % N
    xi2 = (pow(xi2, ri, N) * mu_i) % N
    yi2 = (pow(mu_i, ri, N) * yi2) % N
    pi_s.append(mu_i)
    assert yi2 % N == pow(xi2, e, N)


pi_s = list(reversed(pi_s))
print(len(pi_s))
print(verify_proof(g, y, pi_s[:], logT, 0, N))

io.sendline(str(logT+1).encode())

assert len(pi_s) == logT + 1
for i in pi_s:
    io.sendline(str(i).encode())
io.interactive()
