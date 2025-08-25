from pwn import xor
from uov import uov_1p_pkc as uov # https://github.com/mjosaarinen/uov-py/blob/main/uov.py

names = ['Miku', 'Ichika', 'Minori', 'Kohane', 'Tsukasa', 'Kanade']
pks = [uov.expand_pk(uov.shake256(name.encode(), 43576)) for name in names]
msg = b'SEKAI'

sig = bytes.fromhex(input('Ring signature (hex): '))
assert len(sig) == 112 * 6, 'Incorrect signature length'

t = xor(*[uov.pubmap(sig[i*112:(i+1)*112], pks[i]) for i in range(6)])
assert t == uov.shake256(msg, 44), 'Invalid signature'

print('sekai{testflag}')