from sage.all import *
from pwn import *

context.log_level = 'debug'
# nc chall.lac.tf 31172
io = remote('chall.lac.tf', 31172)
# io = process(['python3', 'shuffler.py'])
io.recvline()
a = int(io.recvline().strip().split(b'=')[1])
c = int(io.recvline().strip().split(b'=')[1])
m = int(io.recvline().strip().split(b'=')[1])

print(f'a={a}, c={c}, m={m}')

io.recvuntil(b"> ")
io.sendline(b"2")
io.recvuntil(b"Here you go: ")
shuffled_secret = bytes.fromhex(io.recvline().strip().decode())
io.recvuntil(b"> ")

def flatter(M):
    from subprocess import check_output
    from re import findall
    z = "[[" + "]\n[".join(" ".join(map(str, row)) for row in M) + "]]"
    ret = check_output(["flatter"], input=z.encode())
    return matrix(M.nrows(), M.ncols(), map(int, findall(b"-?\\d+", ret)))

def babai_cvp(B, t, perform_reduction=True):
    if perform_reduction:
        B = B.LLL(delta=0.75)

    G = B.gram_schmidt()[0]
    b = t
    for i in reversed(range(B.nrows())):
        c = ((b * G[i]) / (G[i] * G[i])).round()
        b -= c * B[i]

    return t - b

def get_shuffle():
    io.sendline(b"1")
    io.sendline(bytes([i for i in range(256)]).hex().encode())
    # print(bytes([i for i in range(256)]).hex())
    io.recvuntil(b"Here you go: ")
    shuffled = bytes.fromhex(io.recvline().strip().decode())
    io.recvuntil(b"> ")
    return shuffled

a0_LCG = 1
c0_LCG = 0
def next():
    global a0_LCG, c0_LCG
    a0_LCG = a0_LCG * a % m
    c0_LCG = (c0_LCG * a + c) % m
    return a0_LCG, c0_LCG

def get_small():
    preds = [next() for _ in range(256)]
    shuffled = get_shuffle()

    s = shuffled[0]
    s_big = shuffled[-1]
    return preds[s], preds[s_big]



k = 80
alist = []
clist = []
for _ in range(k//2):
    (a0, c0), (a1, c1)= get_small()
    alist.append(a0)
    clist.append(c0)
    alist.append(a1)
    clist.append(c1)

mbit = 64

M = matrix(ZZ, k+2, k+1)
M[0]=vector(ZZ,[2**mbit]+clist)
M[1]=vector(ZZ,[0]+alist)
M[2:,1:]=identity_matrix(k)*m

# M = flatter(M)
M = M.LLL()
for i in range(k+2):
    if abs(M[i][0])==2**mbit:
        # print(M[i])
        a0 = alist[0]
        c0 = clist[0]
        guess_seed = (abs(M[i][1]) - c0) * pow(a0, -1, m) % m
        print(guess_seed)

def prev(seed):
    return ((seed-c) * pow(a, -1, m)) % m

for _ in range(64):
    guess_seed = prev(guess_seed)

class LCG:

    def __init__(self, a: int, c: int, m: int, seed: int):
        self.a = a
        self.c = c
        self.m = m
        self.state = seed

    def next(self):
        self.state = (self.a * self.state + self.c) % self.m
        return self.state

L = LCG(a, c, m, guess_seed)
def shuffle_msg(msg: bytes, L: LCG) -> str:

    l = len(msg)

    positions = [L.next() for i in range(l)]

    sorted_msg = sorted(zip(positions, msg))

    output = bytes([c[1] for c in sorted_msg])

    return output
sorted = shuffle_msg(bytes([i for i in range(64)]), L)

raw_secret = [None] * 64
for i in range(64):
    raw_secret[sorted[i]] = shuffled_secret[i]

# print(bytes(raw_secret).hex())

io.sendline(b"3")
io.sendline(bytes(raw_secret).hex())
io.interactive()
