from sage.all import *
from pwn import *
from Crypto.Cipher import ChaCha20_Poly1305

p = 2**130 - 5
def le_bytes_to_num(data):
    """Convert a number from little endian byte format"""
    ret = 0
    for i in range(len(data) - 1, -1, -1):
        ret <<= 8
        ret += data[i]
    return ret

def num_to_16_le_bytes(num):
    """Convert number to 16 bytes in little endian format"""
    ret = [0]*16
    for i, _ in enumerate(ret):
        ret[i] = num & 0xff
        num >>= 8
    return bytearray(ret)

# context.log_level = 'debug'

# io = process(['python3', 'chall.py'])
# nc nostalgic.seccon.games 5000
io = remote('nostalgic.seccon.games', 5000)

io.recvuntil(b"my SPECIAL_MIND is")
SPECIAL_MIND = bytes.fromhex(io.recvline().strip().decode())
io.recvuntil(b"special_rain_enc = ")
special_rain_enc = bytes.fromhex(io.recvline().strip().decode())
io.recvuntil(b"special_rain_tag = ")
special_rain_tag = bytes.fromhex(io.recvline().strip().decode())

def gen():
    io.sendline(b"need")
    ret = io.recvline().strip().decode()
    return bytes.fromhex(ret.split('MIND was')[1])

data = [gen() for _ in range(65)]
tags = [le_bytes_to_num(tag) + 2 ** 129 for tag in data]

vt = vector(ZZ, tags)
M = block_matrix(ZZ, [[p*identity_matrix(1)*100, matrix([vt])*100], [identity_matrix(1)*0, matrix([[200]*len(tags)])], [0, identity_matrix(len(tags))]]).T
M = M.LLL(algorithm='flatter')
M = M.BKZ(block_size=24)

print(M[0])

M = M[:40, 2:]
M2 = M.right_kernel().matrix().LLL(algorithm='flatter')
print(M2[:3])

ve = M2[1]
vte = vt - ve * 2**128
vte = list(vte)
vte0 = vte[0]
vte1 = vte[1:]
vte1 = [v1 - vte0 for v1 in vte1]


M3 = block_matrix(ZZ, [[matrix([vte1])], [p*identity_matrix(len(vte1))]])
M3 = M3.LLL()
print(M3[:3])
vv0 = M3[1,0]
vv1 = vte1[0]

print(vv0.bit_length())

r2 = vv1 * pow(vv0, -1, p) % p
assert (vte1[1] - r2 * M3[1,1]) % p == 0
print(r2)
try:
    r = int(mod(-r2, p).sqrt())
except:
    r = int(mod(r2, p).sqrt())
if r > 2 ** 128:
    r = p - r
print(r.bit_length())
print(hex(r-(r&0x0ffffffc0ffffffc0ffffffc0fffffff)))

x = le_bytes_to_num(special_rain_enc+b'\x01')
s = (le_bytes_to_num(special_rain_tag) + 2**128 - 0x100000000000000100000000000000000 * r - x * r**2) % p
print(hex(s))

for i in range(4):
    target_ct = (le_bytes_to_num(SPECIAL_MIND) + i * 2**128 - s - 0x100000000000000100000000000000000 * r) * pow(r, -2, p) % p
    if target_ct // 2** 128==1:
        break
print(hex(target_ct))
ct = num_to_16_le_bytes(target_ct)
inp = bytes([x^y for x, y in zip(special_rain_enc, ct)])
print(inp)
io.sendline(inp.hex().encode())

io.interactive()
