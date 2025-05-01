#!/usr/local/bin/python3
def fmix128(k):
    k ^= k >> 65
    k *= 0xff51afd7ed558ccdff51afd7ed558ccd
    k &= 0xffffffffffffffffffffffffffffffff
    k ^= k >> 65
    k *= 0xc4ceb9fe1a85ec53c4ceb9fe1a85ec53
    k &= 0xffffffffffffffffffffffffffffffff
    k ^= k >> 65
    return k

def fmix128_2(k):
    k *= 0xff51afd7ed558ccdff51afd7ed558ccd
    k &= 0xffffffffffffffffffffffffffffffff
    k ^= k >> 65
    k *= 0xc4ceb9fe1a85ec53c4ceb9fe1a85ec53
    k &= 0xffffffffffffffffffffffffffffffff
    return k

import random
k = random.getrandbits(128)
k1 = k^(k >> 65)
assert k1^(k1 >> 65) == k
u_inv = pow(0xff51afd7ed558ccdff51afd7ed558ccd*0xc4ceb9fe1a85ec53c4ceb9fe1a85ec53, -1, (2**128))


# 198082268170481019352909704385375310477
k = 198082268170481019352909704385375310477
assert 0xff51afd7ed558ccdff51afd7ed558ccd*0xc4ceb9fe1a85ec53c4ceb9fe1a85ec53*k % (2**128) == k^(k >> 65)
k1 = k^(k >> 65)
assert u_inv*k1 % (2**128) == k

k2 = pow(0xff51afd7ed558ccdff51afd7ed558ccd, -1, (2**128)) * k1 % (2**128)
assert fmix128_2(k2) == k2
k3 = k2^(k2 >> 65)
assert fmix128(k3) == k3
print(k3)

k = int(input('k: '), 0)
if 0 < k < 2**128 and k == fmix128(k):
    print('ictf{REDACTED}')
else:
    print('WRONG')
