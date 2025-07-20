from utils import element_to_int

FLAG = os.environ.get("FLAG", "Alpaca{***************** REDACTED *****************}").encode()
assert len(FLAG) == 52 and FLAG.startswith(b"Alpaca{") and FLAG.endswith(b"}")

pad = os.urandom(len(FLAG))
FLAG = [a ^^ b for a, b in zip(FLAG, pad)]

q = int(input("Missing order: "), 16)
assert not is_prime(q) and q.bit_length() == 256

# `modulus=` ensures consistent modulus behavior across Sage versions and is not relevant to the solution
F = GF(q, name="z", modulus=pari.minpoly(pari.ffgen(q)))
A = random_matrix(F, len(FLAG))[:,:-2]
b = A * random_vector(F, A.ncols()) + vector(F, FLAG) * F.random_element()

print([[element_to_int(elem) for elem in row] for row in A])
print([element_to_int(elem) for elem in b])
print(pad)
