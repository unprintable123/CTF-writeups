from utils import element_to_int
import os

FLAG = os.environ.get("FLAG", "Alpaca{***************** REDACTED *****************}").encode()
assert len(FLAG) == 52 and FLAG.startswith(b"Alpaca{") and FLAG.endswith(b"}")

order = 0xdead1337cec2a21ad8d01f0ddabce77f57568d649495236d18df76b5037444b1
# `modulus=` ensures consistent modulus behavior across Sage versions and is not relevant to the solution
F = GF(order, name="z", modulus=pari.minpoly(pari.ffgen(order)))
A = random_matrix(F, len(FLAG))[:,:-2]
b = A * random_vector(F, A.ncols()) + vector(F, FLAG) * F.random_element()

print([[element_to_int(elem) for elem in row] for row in A])
print([element_to_int(elem) for elem in b])
