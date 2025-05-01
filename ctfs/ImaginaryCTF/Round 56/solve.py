from sage.all import *
import os, random
from tqdm import tqdm
from concurrent.futures import ProcessPoolExecutor

def Babai_closest_vector(M, G, target):
    # Babai's Nearest Plane algorithm
    small = target
    for i in reversed(range(2)):
        c = ((small * G[i]) / (G[i] * G[i])).round()
        small -= M[i] * c
    return target - small

c = 0x9f3887bfd91f1f50ed77e7f1c90aa277
# c = 0xa60668fd9f053fe4d361f90f40fdd747
# assert 0x9f3887bfd91f1f50ed77e7f1c90aa277 * 0xa60668fd9f053fe4d361f90f40fdd747 % (2**128) == 1
nbits = 34

for _ in range(1024):

    while True:
        k = random.getrandbits(128)
        k2 = k ^ (k >> 65)
        if k % 2 == 0:
            continue
        c = k2 * pow(k, -1, 2**128) % (2**128)
        if c & 0xff == 0x77:
            break

    # dinf c*k == k ^ (k >> 65)

    c0 = (c - 1) // 2
    c0_inv = pow(c0, -1, 2**127)

    M = matrix(ZZ, [[c0, 1], [2**64, 0]])
    M = M.LLL()
    if M[0][1] < 2**29 or M[0][0] < 2**30:
        continue
    G = M.gram_schmidt()[0]
    break

print(hex(c), hex(k), hex(k2))
assert c * k % (2**128) == k ^ (k >> 65)

diff_k = (k2 - k) // 2
print(diff_k)

c0 = (c - 1) // 2
c0_inv = pow(c0, -1, 2**127)

MOD_nbits = 2**nbits - 1
c_65 = c % (2**65)
c0_64_nbits = -c0 % (2**(64+nbits))
MOD_64_nbits = 2**(64+nbits) - 1



M = matrix(ZZ, [[c0, 1], [2**64, 0]])
M = M.LLL()
print(M)
G = M.gram_schmidt()[0]

for guess_diff_k in tqdm(range(-2**(nbits-1), 2**(nbits-1))):

    k_last_bits = guess_diff_k * c0_inv & MOD_nbits
    k2_last_bits = (guess_diff_k*2 + k_last_bits) & MOD_nbits
    k_middle_bits = k2_last_bits ^ k_last_bits
    # print(hex(k_middle_bits), hex(k>>65))

    # (c0//2) * k_middle_bits|??...?|k_last_bits is small % 2**(64+nbits)
    # (c0*2**(nbits-1)) * ??? + (c0//2) * k_middle_bits|00...0|k_last_bits is small % 2**(64+nbits)

    # target_k_mid = ((k & (2**65-1)) >> nbits)
    # print(hex((c0)*target_k_mid % 2**(64)))

    t0 = (k_middle_bits << 65) | k_last_bits 
    # t = (-(c0) * t0 % (2**(64+nbits))) >> nbits
    t = (c0_64_nbits * t0 & MOD_64_nbits) >> nbits
    # print(hex(t))

    target = vector(ZZ, [t, 0])
    k_middle_bits2 = Babai_closest_vector(M, G, target)[1]
    # k_middle_bits2 = target_k_mid
    # assert target_k_mid == k_middle_bits2, f"{target_k_mid}, {k_middle_bits2}"

    k_last_bits2 = k_last_bits | (k_middle_bits2 << nbits)
    # print(hex(k_last_bits2))
    k2_last_bits2 = c_65 * k_last_bits2 & 0x1ffffffffffffffff # % (2**65)
    # print(hex(k2_last_bits2))
    k_first_bits = (k2_last_bits2 ^ k_last_bits2) & 0x7fffffffffffffff
    geuss_k = (k_first_bits << 65) | k_last_bits2
    if (c * geuss_k) % (2**128) == geuss_k ^ (geuss_k >> 65):
        break

