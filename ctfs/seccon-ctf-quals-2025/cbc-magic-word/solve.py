from pwn import *
import base64
import string

# context.log_level = 'debug'
def bxor(a, b):
    assert len(a) == len(b)
    return bytes(x ^ y for x, y in zip(a, b))

# io = process(['python3', 'server.py'])
# nc cbc-magic-word.seccon.games 3333
io = remote('cbc-magic-word.seccon.games', 3333)
# magic_key = io.recvline().strip()
# print(magic_key, len(magic_key))
io.recvuntil(b"encrypted_word: ")

encrypted_word = base64.b64decode(io.recvline().strip().decode())
assert len(encrypted_word) % 16 == 0

example = '{"key": "ZTrQjioAIYTMxLiGsYkaHJgPWqWwkiLgQGKuuYbrZULvdGomsWeZFAxKxvckhwpUnsTOKDezKGspkybKIfZTsoCWjRsjQMSgiJIFAKkhNrjxlSuJfWwqaLuFAcgjOuMhRiyIgzBSrATpNcuABReXmg"}'

base_iv = encrypted_word[:16]
encrypted = encrypted_word[16:]

cnt = 0
def oracle(iv: bytes, encrypted):
    global cnt
    cnt += 1
    input = bytes(iv) + bytes(encrypted)
    io.sendlineafter(b'>', base64.b64encode(input))
    res = io.recvline().strip().decode()
    # print(res)
    if 'ok' in res:
        return 2
    if 'json' in res:
        return 1
    if 'decrypt' in res:
        return 0


def find_byte(iv, encrypted, pos):
    assert pos <= 12
    head = [0, 1, None, None, None, None, None, None]
    
    ret = [False, False]
    for i in range(2):
        iv0 = bytearray(iv)
        iv0[pos] ^= 0x80 + 0x20 * i
        iv0[pos+1] ^= 0xc0
        output = oracle(iv0, encrypted)
        ret[i] = output > 0
    # print(ret)
    if ret[0]:
        head[2] = 0
    elif ret[1]:
        head[2] = 1
    else:
        # c0 or c1
        iv0 = bytearray(iv)
        iv0[pos] ^= 0x8f
        iv0[pos+1] ^= 0xc0
        output = oracle(iv0, encrypted)
        if output > 0:
            head[2] = 0
        else:
            head[2] = 1
    

    ret = [False, False]
    for i in range(2):
        iv0 = bytearray(iv)
        iv0[pos] ^= 0x80 + 0x20 * (1 - head[2]) + 0x10 * i
        iv0[pos+1] ^= 0xc0
        iv0[pos+2] ^= 0xc0
        output = oracle(iv0, encrypted)
        ret[i] = output > 0
    # print(ret)
    if ret[0]:
        head[3] = 0
    elif ret[1]:
        head[3] = 1
    else:
        # e0 or ed
        iv0 = bytearray(iv)
        iv0[pos] ^= 0x80 + 0x20 * (1 - head[2]) + 0xf
        iv0[pos+1] ^= 0xc0
        iv0[pos+2] ^= 0xc0
        output = oracle(iv0, encrypted)
        if output > 0:
            head[3] = 0
        else:
            head[3] = 1
    
    ret = [False] * 4
    for i in range(4):
        iv0 = bytearray(iv)
        iv0[pos] ^= 0x80 + 0x20 * (1 - head[2]) + 0x10 * (1 - head[3]) + 0x4 * i
        iv0[pos+1] ^= 0xc0
        iv0[pos+2] ^= 0xc0
        iv0[pos+3] ^= 0xc0
        output = oracle(iv0, encrypted)
        ret[i] = output > 0
    # print(ret)
    assert sum(ret) == 1
    for i in range(4):
        if ret[i]:
            head[4] = i // 2
            # head[5] = i % 2 # 因为有f4所以这一位不能信
    
    ret = [False] * 4
    for i in range(4):
        iv0 = bytearray(iv)
        iv0[pos] ^= 0x80 + 0x20 * head[2] + 0x10 * head[3] + 0x8 * head[4] + 0x2 * i
        iv0[pos+1] ^= 0xc0
        output = oracle(iv0, encrypted)
        ret[i] = output > 0
    # print(ret)

    assert sum(ret) == 3
    for i in range(4):
        if not ret[i]:
            head[5] = i // 2
            head[6] = i % 2
    
    ret = [False] * 8
    for i in range(8):
        iv0 = bytearray(iv)
        iv0[pos] ^= 0x80 + 0x20 * (1 - head[2]) + 0x10 * (1 - head[3]) + 0x8 * head[4] + 0x4 * (1-head[5]) + 0x2 * head[6] + (i // 4)
        iv0[pos+1] ^= 0xc0 + 0x10 * (i % 4)
        iv0[pos+2] ^= 0xc0
        iv0[pos+3] ^= 0xc0
        output = oracle(iv0, encrypted)
        ret[i] = output > 0

    # print(ret)
    assert sum(ret) == 1
    if sum(ret[:4]) == 1:
        head[7] = 0
    else:
        head[7] = 1
    # print(hex(magic_key[16:32][pos]))
    # print(sum((1<<(7-i)) * head[i] for i in range(8)))
    # assert magic_key[16:32][pos] == sum((1<<(7-i)) * head[i] for i in range(8))
    
    return sum((1<<(7-i)) * head[i] for i in range(8))

def forge_json(iv, encrypted, first_13_bytes, pos):
    target = b'{"key": "'
    target = bxor(target, first_13_bytes[:len(target)])
    target = target + b'\x00' * (16 - len(target))
    new_iv = bxor(iv, target)
    ret_uppercase = []
    ret_lowercase = []
    for c in string.ascii_letters:
        iv1 = bytearray(new_iv[:])
        iv1[pos] ^= ord(c) ^ ord('"')
        output = oracle(iv1, encrypted)
        if ord(c) >= ord('a'):
            ret_lowercase.append(output)
        else:
            ret_uppercase.append(output)
    # print(ret_uppercase)
    # print(ret_lowercase)
    if sum(ret_uppercase) == 26:
        assert sum(ret_lowercase) == 51
        real_c = ret_lowercase.index(1)
        return real_c + ord('a')
    else:
        assert sum(ret_lowercase) == 26
        assert sum(ret_uppercase) == 51
        real_c = ret_uppercase.index(1)
        return real_c + ord('A')
    


def solve_block(iv, encrypted, first_block=False, last_block: bool=False):
    known_bytes = []
    if first_block:
        known_bytes = list(bytes(b'{"key": "'))
    for pos in range(len(known_bytes), 13-int(last_block)):
        print(pos)
        known_bytes.append(find_byte(iv, encrypted, pos))
    # print(known_bytes)
    known_bytes = known_bytes + [None] * (16 - len(known_bytes))
    for pos in range(13-int(last_block), 16-int(last_block)):
        known_bytes[pos] = forge_json(iv, encrypted, known_bytes, pos)
    if last_block:
        known_bytes[-1] = ord('"')
    return bytes(known_bytes)

txt = ""
block_num = len(encrypted) // 16 - 3
for i in range(block_num):
    print("Solving block", i)
    iv = encrypted_word[16*i:16*(i+1)]
    out = solve_block(iv, encrypted[16*i:], first_block=(i==0), last_block=(i==block_num-1))
    # print(out, magic_key[16*i:16*(i+1)])
    print(out)
    txt += out.decode()
txt += '}'

io.sendline(txt)
io.interactive()

