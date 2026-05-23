from Crypto.Util.number import *

PBITS, NDAT = 137, 137

with open("flag.txt", "rb") as f:
	m = int.from_bytes(f.read())

N = getPrime(PBITS) * getPrime(PBITS)
e = getRandomRange(731, N)
print(f"{N = }")

lcg = lambda s: (s * 3 + 1337) % N

for i in range(NDAT):
	print(pow(m, e:=lcg(e), N) + pow(m, e:=lcg(e), N))

	# Internal audit
	e = getRandomRange(731, N)
	print(f"[DEBUG] {e = }")
