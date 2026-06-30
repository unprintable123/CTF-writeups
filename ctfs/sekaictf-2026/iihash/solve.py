from pwn import *
from subprocess import check_output

from sage.all import *
from xxhash_demo import *
from pwn import process, remote, context

# context.log_level = "debug"

def rshift_inv(hash, shift):
    recovered = 0
    for i in range(64):
        high = (hash >> (63 - i)) & 1
        high = high << (63 - i)
        recovered += high
        hash = hash ^ (high ^ (high >> shift))
    return recovered

def avalanche_inv(hash):
    hash = rshift_inv(hash, 32)
    hash = (hash * pow(PRIME_MX1, -1, 2**64)) % 2**64
    hash = rshift_inv(hash, 37)
    return hash

def Babai_closest_vector(M, G, target):
    # Babai's Nearest Plane algorithm
    small = target
    for _ in range(1):
        for i in reversed(range(M.nrows())):
            c = ((small * G[i]) / (G[i] * G[i])).round()
            small -= M[i] * c
    return target - small

def solve_sum(m1, m2, m3, t):
    def get_possible_muls(m):
        results = {}
        M = matrix([[-2**64, 1], [m, 0]])
        M = M.LLL()
        G = M.gram_schmidt()[0]
        v = M[0]
        if v[0]*v[1] < 0:
            v = M[1]
        if v[0] < 0:
            v = -v
        assert (v[0] + v[1]*2**64) % m == 0
        bits = 11
        for i in range(2**bits):
            c = vector([2**(61-bits)*i+2**34, 2**(61-bits)*i+2**34])
            close_c = Babai_closest_vector(M, G, c)
            kk = int((close_c[0] + close_c[1]*2**64)//m)
            dk = int((v[0] + v[1]*2**64)//m)
            for _ in range(2**11):
                muls = kk * m
                assert (close_c[0] < 2**64) and (close_c[1] < 2**64)
                # assert (muls ^ (muls >> 64)) % 2**64 == int(close_c[0] ^ close_c[1]), f"{hex(muls)}, {hex(close_c[0]), hex(close_c[1])}"
                results[int(close_c[0] ^ close_c[1])] = kk
                close_c += v
                kk += dk
        return results
    
    possible_muls1 = get_possible_muls(m1)
    possible_muls2 = get_possible_muls(m2)
    mean = 2*(sum(possible_muls1.keys()) + sum(possible_muls2.keys())) // (len(possible_muls1) + len(possible_muls2))
    M = matrix([[-2**64, 1], [m3, 0]])
    M = M.LLL()
    G = M.gram_schmidt()[0]
    c = Babai_closest_vector(M, G, vector([(2**61)^(t-mean-randint(-2**36,2**36)), 2**61+randint(2**32, 2**33)]))
    assert (c[0] + c[1]*2**64) % m3 == 0
    t0 = t - int(c[0] ^ c[1])
    assert t0 < 2 ** 50, f"{t0}, {mean}"
    for u in possible_muls1:
        if (t0 - u) in possible_muls2:
            # print("find:", u, t0 - u, int(c[0] ^ c[1]))
            return possible_muls1[u], possible_muls2[t0 - u], int(c[0] + c[1]*2**64)//m3
    raise ValueError("No solution found")

def mul_128_fold(a, b):
    c = a * b
    return (c >> 64) ^ (c % 2**64)

def pack_key_u64(key):
    return [make_u64(key[i*8:i*8+8]) for i in range(len(key)//8)]

def merge_acc_inv(k1, start1, t1, k2, start2, t2):
    target1 = avalanche_inv(t1)
    target2 = avalanche_inv(t2)
    key1 = pack_key_u64(k1)
    key2 = pack_key_u64(k2)
    acc = [None] * 8
    acc[0] = key1[0] ^ 1
    acc[1] = ((target1 - start1) % 2**64) ^ key1[1]
    acc[2] = key1[2]
    acc[4] = key1[4]
    acc[6] = key1[6]
    v1, v2, v3 = solve_sum(acc[2] ^ key2[2], acc[4] ^ key2[4], acc[6] ^ key2[6], 
                           (target2 - start2 - mul_128_fold(acc[0]^key2[0], acc[1]^key2[1])) % 2**64)
    acc[3] = v1 ^ key2[3]
    acc[5] = v2 ^ key2[5]
    acc[7] = v3 ^ key2[7]
    assert xxh3_merge_accs(acc, k1, start1) == t1
    assert xxh3_merge_accs(acc, k2, start2) == t2
    print(v1, v2, v3)
    for i in range(8):
        assert acc[i] < 2**64, f"{acc}, {i}, {hex(acc[i])}"
    return acc

def acc_512_128_inv(acc, input, secret):
    for i in reversed(range(8)):
        input_val = make_u64(input[i*8:i*8+8])
        acc[i^1] = (acc[i^1] - input_val) % 2**64
        input_val ^= make_u64(secret[i*8:i*8+8])
        acc[i] = (acc[i] - (input_val >> 32) * (input_val % 2**32)) % 2**64


def preimage_attack(hashed, secret):
    m = int.from_bytes(hashed, "big")
    m_high = m >> 64
    m_low = m & 0xFFFFFFFFFFFFFFFF
    fake_input = b"a"*1024
    acc = merge_acc_inv(secret[11:], (len(fake_input) * PRIME64_1) & 0xFFFFFFFFFFFFFFFF, (m_low), secret[-75:], ~(len(fake_input) * PRIME64_2) & 0xFFFFFFFFFFFFFFFF, (m_high))
    acc_512_128_inv(acc, fake_input[-64:], secret[-71:])
    for i in reversed(range(15)):
        if i==0 or i==1:
            continue
        acc_512_128_inv(acc, fake_input[i*64:i*64+64], secret[8*i:])

    def solve_512(target_acc, secret):
        def make_original_acc():
            original_acc = [None] * 8
            original_acc[0] = PRIME32_3
            original_acc[1] = PRIME64_1
            original_acc[2] = PRIME64_2
            original_acc[3] = PRIME64_3
            original_acc[4] = PRIME64_4
            original_acc[5] = PRIME32_2
            original_acc[6] = PRIME64_5
            original_acc[7] = PRIME32_1
            return original_acc

        acc0 = make_original_acc()
        acc1 = make_original_acc()

        guess_input = secret[:64] + secret[8:72]
        for i in range(8):
            for j in range(4):
                guess_input[i*8+j] = 0
        for i in range(8, 16):
            for j in range(4, 8):
                guess_input[i*8+j] = 0
        xxh3_acc_128(acc0, guess_input, secret, 2)
        diff = [(a-b)%2**64 for a, b in zip(target_acc, acc0)]
        def set_u32(guess_input, u32, start_idx):
            for i in range(4):
                guess_input[start_idx+i] = (u32 >> (8*i)) & 0xFF
        
        for i in range(8):
            set_u32(guess_input, diff[i^1]%(2**32), 8*i)
            set_u32(guess_input, diff[i^1]>>32, 8*i+4+64)
        xxh3_acc_128(acc1, guess_input, secret, 2)
        assert all(a==b for a, b in zip(acc1, target_acc))
        return bytes(guess_input)

    real_input_128 = solve_512(acc[:], secret[:])
    fake_input = real_input_128 + fake_input[128:]
    return fake_input

def try_find_collision(v, secret_upper_lsb3, bound=16):
    if max([abs(u) for u in v.list()]) >= bound:
        return None
    left = v.hamming_weight() // 2
    left = min(i for i in range(left, 15) if v[:i].hamming_weight() == left)
    left_part = {}
    for _ in range(256):
        s = 0
        t = []
        for i in range(left):
            while True:
                u = randint(0, bound-1)
                u2 = u + v[i]
                if u2 < bound and u2 >= 0:
                    break
            t.append(u)
            s += (u2 ^ secret_upper_lsb3[i]) - (u ^ secret_upper_lsb3[i])
        left_part[s] = t
    find = False
    for _ in range(256):
        s = 0
        t = []
        for i in range(left, 15):
            while True:
                u = randint(0, bound-1)
                u2 = u + v[i]
                if u2 < bound and u2 >= 0:
                    break
            t.append(u)
            s += (u2 ^ secret_upper_lsb3[i]) - (u ^ secret_upper_lsb3[i])
        if -s in left_part:
            find = True
            t = left_part[-s] + t
            break
    if find:
        return t
    else:
        return None

def crack_seed(oracle_func):
    secrets_u64 = [make_u64(SECRET_DEFAULT[i*8:i*8+8]) for i in range(24)]
    seed_range = [0, 2**32-1] + [2**32-secrets_u64[2*i]%2**32 for i in range(8)] + [secrets_u64[2*i+1]%2**32 for i in range(8)]
    seed_range = sorted(seed_range)
    for ridx in range(len(seed_range)-1):
        seed_lower32 = (seed_range[ridx] + seed_range[ridx+1]) // 2
        secrets_u32_adjusted = []
        for i in range(12):
            u32 = secrets_u64[2*i] % 2**32
            if u32 + seed_lower32 >= 2**32:
                secrets_u32_adjusted.append(u32 - 2**32)
            else:
                secrets_u32_adjusted.append(u32)
            u32 = secrets_u64[2*i+1] % 2**32
            if u32 - seed_lower32 < 0:
                secrets_u32_adjusted.append(u32 + 2**32)
            else:
                secrets_u32_adjusted.append(u32)
        M = matrix(ZZ, [[1, -1]*7+[1], secrets_u32_adjusted[:15]])
        M = M.right_kernel().matrix()
        M = M.LLL()
        for seed_upper32_lsb in range(16):
            seed_tmp = seed_lower32 + (seed_upper32_lsb << 32)
            secret_upper_lsb4 = []
            for i in range(12):
                u = (secrets_u64[2*i] + seed_tmp) >> 32
                u = u % 16
                secret_upper_lsb4.append(u)
                u = (secrets_u64[2*i+1] - seed_tmp) >> 32
                u = u % 16
                secret_upper_lsb4.append(u)
            secret_upper_lsb4 = secret_upper_lsb4[:15]
            correct = True
            def check(t, v, secret_upper_lsb, offset=0):
                t1 = [u ^ secret_upper_lsb[i] for i, u in enumerate(t)]
                t2 = [(u + v[i]) ^ secret_upper_lsb[i] for i, u in enumerate(t)]
                payload1 = b"".join((u*2**(32+offset)).to_bytes(8, "little")+b"\x00"*56 for u in t1)+b"\x00"*64
                payload2 = b"".join((u*2**(32+offset)).to_bytes(8, "little")+b"\x00"*56 for u in t2)+b"\x00"*64
                assert payload1 != payload2
                return oracle_func(payload1) == oracle_func(payload2)
            for v in M:
                t = try_find_collision(v, secret_upper_lsb4)
                if t is not None:
                    if not check(t, v, secret_upper_lsb4):
                        correct = False
                        break
            if correct:
                print(f"find collison:", seed_upper32_lsb, ridx)
                def find_next(seed_lower32, seed_upper32_lsb, known_lsb_bits):
                    for next_bit in [0, 1]:
                        seed_tmp = next_bit * 2**(32+known_lsb_bits) + (seed_upper32_lsb << 32) + seed_lower32
                        secret_upper_lsb = []
                        for i in range(12):
                            u = (secrets_u64[2*i] + seed_tmp) >> (32+known_lsb_bits-3)
                            u = u % 16
                            secret_upper_lsb.append(u)
                            u = (secrets_u64[2*i+1] - seed_tmp) >> (32+known_lsb_bits-3)
                            u = u % 16
                            secret_upper_lsb.append(u)
                        secret_upper_lsb = secret_upper_lsb[:15]
                        correct = True
                        for v in M:
                            t = try_find_collision(v, secret_upper_lsb)
                            if t is not None:
                                if not check(t, v, secret_upper_lsb, offset=known_lsb_bits-3):
                                    correct = False
                                    break
                        if correct:
                            return next_bit
                    return None
                known_lsb_bits = 4
                while known_lsb_bits < 32:
                    next_bit = find_next(seed_lower32, seed_upper32_lsb, known_lsb_bits)
                    if next_bit is None:
                        break
                    seed_upper32_lsb += next_bit << known_lsb_bits
                    known_lsb_bits += 1
                if known_lsb_bits == 32:
                    print("crack seed upper 32:", hex(seed_upper32_lsb))
                    seed_tmp = seed_lower32 + (seed_upper32_lsb << 32)
                    secret_upper_lsb = []
                    for i in range(12):
                        u = (secrets_u64[2*i] + seed_tmp) >> 32
                        u = u % 2**32
                        secret_upper_lsb.append(u)
                        u = (secrets_u64[2*i+1] - seed_tmp) >> 32
                        u = u % 2**32
                        secret_upper_lsb.append(u)
                    secret_upper_lsb = secret_upper_lsb[:15]
                    def check2(l1, l2):
                        def make_payload(l):
                            if len(l) < 4:
                                l = l + [0]*(4-len(l))
                            assert max(l) < 2**32, l
                            payload = (secret_upper_lsb[0]*2**32 + l[0]).to_bytes(8, "little")+b"\x00"*56+\
                                    ((secret_upper_lsb[1]^1)*2**32 + l[1]).to_bytes(8, "little")+b"\x00"*56+\
                                    ((secret_upper_lsb[2]^3)*2**32 + l[2]).to_bytes(8, "little")+b"\x00"*56+\
                                    (secret_upper_lsb[3]*2**32 + l[3]).to_bytes(8, "little")
                            return payload + b"\x00"*(1024-len(payload))
                        d = sum(l1) - sum(l2)
                        if abs(d) < 2**32:
                            if d>0:
                                payload1 = make_payload([0]+l1)
                                payload2 = make_payload([d]+l2)
                            else:
                                payload1 = make_payload([abs(d)]+l1)
                                payload2 = make_payload([0]+l2)
                        else:
                            if d > 0:
                                payload1 = make_payload([0]+l1+[0])
                                payload2 = make_payload([2**32-1]+l2+[d-2**32+1])
                            else:
                                payload1 = make_payload([2**32-1]+l1+[abs(d)-2**32+1])
                                payload2 = make_payload([0]+l2+[0])
                        assert payload1 != payload2
                        return oracle_func(payload1) == oracle_func(payload2)
                    
                    def find_next2(seed_lower_lsb, known_lsb_bits):
                        u = 2**(known_lsb_bits+1) // 3
                        for next_bit in [0, 1]:
                            seed_tmp = next_bit * 2**known_lsb_bits + seed_lower_lsb
                            s1 = (secrets_u64[1] - seed_tmp) % 2**(known_lsb_bits+1)
                            s2 = (secrets_u64[2] + seed_tmp) % 2**(known_lsb_bits+1)
                            if check2([s1^(3*u), s2], [s1, s2^(u)]):
                                return next_bit
                        return None
                    def recover(seed_lower_lsb):
                        known_lsb_bits = 1
                        while known_lsb_bits < 32:
                            next_bit = find_next2(seed_lower_lsb, known_lsb_bits)
                            if next_bit is None:
                                break
                            seed_lower_lsb += next_bit * 2**known_lsb_bits
                            known_lsb_bits += 1
                        if known_lsb_bits == 32:
                            print("crack seed lower 32:", hex(seed_lower_lsb))
                            return seed_lower_lsb
                    seed_lower_lsb = recover(0) or recover(1)
                    if seed_lower_lsb is not None:
                        seed = seed_upper32_lsb << 32 | seed_lower_lsb
                        print("find full seed:", hex(seed))
                        return seed

io = process(["sage", "challenge.py"])
io.recvline()
PoW = check_output(io.recvline().strip().decode(), shell=True).strip()
print("PoW:", PoW)
io.sendline(PoW)

cnt = 0
def get_hash(data):
    global cnt
    cnt += 1
    io.recvuntil(b"> ")
    io.sendline(b"1")
    io.sendline(data.hex().encode())
    io.recvuntil(b"Hash: ")
    return bytes.fromhex(io.recvline().strip().decode())

seed = crack_seed(get_hash)
assert seed is not None
secret = SECRET_DEFAULT[:]
secret_u64 = [make_u64(secret[i*8:i*8+8]) for i in range(24)]
for i in range(12):
    secret_u64[2*i] += seed
    secret_u64[2*i+1] -= seed
secret = [] 
for i in range(24):
    secret += (secret_u64[i] % 2**64).to_bytes(8, 'little')
data = preimage_attack(b"Give me the flag", secret)
print(xxh3_128_digest(data, seed=seed))

print(cnt)

io.recvuntil(b"> ")
io.sendline(b"2")
io.sendline(data.hex().encode())
io.interactive()






