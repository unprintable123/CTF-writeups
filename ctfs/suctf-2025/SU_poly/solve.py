from pwn import *
from sage.all import *
from hashlib import md5

import random
from mtcrack import MtCracker, Mt19937
from tqdm import tqdm




# cracker = MtCracker()
# for i in tqdm(range(21333)):
# 	cracker.update(i * 44 + 40 + 44, 0, 1 << (i+1))

# bits = cracker.solver.solve()

# save(bits, "bits.sobj")

bits = load("bits.sobj")

def eval_bit(bit, val):
	return (bit & val).bit_count() & 1

conn = remote("1.95.46.185", 10005)
# conn = process(["sage", "main.sage"])
conn.recvuntil("🎁 :".encode())
gift = eval(conn.recvline().decode("ascii"))
assert len(gift) == 21333
ret = []
for i in range(21333):
	if all(x % 2 == 0 for x in gift[i][::2]):
		ret.append(0)
	else:
		ret.append(1)


# random.seed(18787)
# SUPOLY = [random.randrange(0, 0xfffffffffffffffffffffffffffffffe) for _ in range(11)]
# gift = []
# for i in range(21333):
# 	coef = [random.randrange(0, 0xfffffffffffffffffffffffffffffffe) for _ in range(11)]
# 	gift.append(coef[-1] & 1)

v = 1
for i in range(len(ret)):
	v ^= ret[i] << (i + 1)


bits = [eval_bit(b, v) for b in bits]


state = [bits[0] << (Mt19937.w - 1)]
bits = bits[1:]
# from LSB to MSB
for i in range(0, len(bits), Mt19937.w):
	_ = "".join("1" if x else "0" for x in bits[i : i + Mt19937.w])
	state.append(int(_[::-1], 2))

state.append(624)

rng = random.Random()
rng.setstate((3, tuple(state), None))

SUPOLY_LIST = [rng.randrange(0, 0xfffffffffffffffffffffffffffffffe) for _ in range(11)]
# for a, b in zip(SUPOLY, SUPOLY2):
# 	assert a == b

for i in tqdm(range(21333)):
	for j in range(10):
		rng.randint(0, 0xfffffffffffffffffffffffffffffffe)

	assert rng.randint(0, 0xfffffffffffffffffffffffffffffffe) % 2 == ret[i]


PR = PolynomialRing(Zmod(0xfffffffffffffffffffffffffffffffe), "x")

SUPOLY = PR(SUPOLY_LIST[::-1])
print(SUPOLY_LIST)
print(SUPOLY)
print(SUPOLY)
print()
conn.sendline(md5(str(SUPOLY.list()).encode()).hexdigest())
conn.interactive()

def local_gift():
	random.seed(8787)
	gift = []
	for i in range(21333):
		coef = [random.randrange(0, 0xfffffffffffffffffffffffffffffffe) for _ in range(11)]
		gift.append(coef[-1] & 1)
	return gift

def solve(gift):
	assert len(gift) == 21333
	print("Solver start")
	cracker = MtCracker()
	for i in tqdm(range(len(gift))):
		cracker.update(i * 44 + 40, 0, gift[i])

	print("Update complete")

	rng = Mt19937()
	rng.state = cracker.solve()[:]

	for i in tqdm(range(21333)):
		for j in range(40):
			rng.rand()

		assert rng.rand() % 2 == gift[i]
		for j in range(3):
			rng.rand()


# if __name__ == "__main__":
# 	# solve(local_gift())
# 	solve(remote_gift())