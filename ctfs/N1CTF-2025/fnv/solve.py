from pwn import *
import random, os
from tqdm import tqdm

io = process(['python3', 'server.py'])
io.recvuntil('⚙️'.encode())
a, b, c, m, x = eval(io.recvline().decode())
io.recvuntil('🎯'.encode())
target = int(io.recvline().decode())

print(f'params: {(a, b, c, m, x)}')
print(f'target: {target}')

def hash(start_x, msg):
    x0 = start_x
    for byte in msg:
        for bit in f'{byte:08b}':
            x0 = ((x0 * a + b + int(bit)) ^ c) % m
    return x0

def hash_inv(target_x, msg):
    x0 = target_x
    a_inv = pow(a, -1, m)
    for byte in reversed(msg):
        for bit in reversed(f'{byte:08b}'):
            x0 = (((x0 ^ c) - b - int(bit)) * a_inv) % m
    return x0

assert hash_inv(hash(x, b"hello world"), b"hello world") == x

start_to_target = b""
target_to_target = list(set(os.urandom(4) for _ in range(2**20)))

cur_bits = 0

while cur_bits < 128:
    # build next 8 bits
    target_with_lower_bits = hash(x, start_to_target)
    cur_bits += 16
    found = False
    mask = (1 << cur_bits) - 1
    for msg in tqdm(target_to_target):
        next_target = hash(target_with_lower_bits, msg)
        if next_target & mask == target & mask:
            start_to_target += msg
            print(f'Found message chunk: {msg.hex()}')
            found = True
            break
    assert found
    new_target_to_target = []
    look_uptable1 = {}
    look_uptable2 = {}
    for msg in tqdm(target_to_target):
        mid1 = hash(target, msg) & mask
        mid2 = hash_inv(target, msg) & mask
        if mid1 not in look_uptable1:
            look_uptable1[mid1] =[]
        look_uptable1[mid1].append(msg)
        if mid2 not in look_uptable2:
            look_uptable2[mid2] =[]
        look_uptable2[mid2].append(msg)
    for mid, msg1_list in look_uptable1.items():
        if mid in look_uptable2:
            msg2_list = look_uptable2[mid]
            for msg1 in msg1_list:
                for msg2 in msg2_list:
                    new_target_to_target.append(msg1 + msg2)
    target_to_target = new_target_to_target[:2**20]





