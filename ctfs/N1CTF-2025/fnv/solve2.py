from pwn import *
import random, os
from tqdm import tqdm

context.log_level = 'debug'

def hash(start_x, msg):
    x0 = start_x
    for byte in msg:
        for bit in f'{byte:08b}':
            x0 = ((x0 * a + b + int(bit)) ^ c) % m
            # print(x0)
    return x0

io = process(['python3', 'server.py'])
# io = remote('60.205.163.215', 13315)
io.recvuntil('⚙️'.encode())
a, b, c, m, x = eval(io.recvline().decode())
io.recvuntil('🎯'.encode())
target = int(io.recvline().decode())

print(f'params: {(a, b, c, m, x)}')
print(f'target: {target}')

a_inv = pow(a, -1, m)

assert m == 2 ** 128

io2 = process(['./run'])
io2.sendline(" ".join(map(str, (a, b, c, x, a_inv))).encode())
io2.recvuntil(b'test:')
print(io2.recvline().decode())
print(hash(x, b"test"))
io2.recvuntil(b'Enter target hash value:\n')
io2.sendline(str(target).encode())
io2.recvuntil(b'Final message:')
msg_hex = io2.recvline().strip().decode()
print(f'Found message (hex): {msg_hex}')

msg = bytes.fromhex(msg_hex)
assert hash(x, msg) == target, f"Hash mismatch: {hex(hash(x, msg))} != {hex(target)}"

io.sendline(msg.hex().encode())
io.interactive()