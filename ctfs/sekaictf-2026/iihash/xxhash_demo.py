import os

SECRET_DEFAULT = [
    0xb8, 0xfe, 0x6c, 0x39, 0x23, 0xa4, 0x4b, 0xbe, 0x7c, 0x01, 0x81, 0x2c, 0xf7, 0x21, 0xad, 0x1c,
    0xde, 0xd4, 0x6d, 0xe9, 0x83, 0x90, 0x97, 0xdb, 0x72, 0x40, 0xa4, 0xa4, 0xb7, 0xb3, 0x67, 0x1f,
    0xcb, 0x79, 0xe6, 0x4e, 0xcc, 0xc0, 0xe5, 0x78, 0x82, 0x5a, 0xd0, 0x7d, 0xcc, 0xff, 0x72, 0x21,
    0xb8, 0x08, 0x46, 0x74, 0xf7, 0x43, 0x24, 0x8e, 0xe0, 0x35, 0x90, 0xe6, 0x81, 0x3a, 0x26, 0x4c,
    0x3c, 0x28, 0x52, 0xbb, 0x91, 0xc3, 0x00, 0xcb, 0x88, 0xd0, 0x65, 0x8b, 0x1b, 0x53, 0x2e, 0xa3,
    0x71, 0x64, 0x48, 0x97, 0xa2, 0x0d, 0xf9, 0x4e, 0x38, 0x19, 0xef, 0x46, 0xa9, 0xde, 0xac, 0xd8,
    0xa8, 0xfa, 0x76, 0x3f, 0xe3, 0x9c, 0x34, 0x3f, 0xf9, 0xdc, 0xbb, 0xc7, 0xc7, 0x0b, 0x4f, 0x1d,
    0x8a, 0x51, 0xe0, 0x4b, 0xcd, 0xb4, 0x59, 0x31, 0xc8, 0x9f, 0x7e, 0xc9, 0xd9, 0x78, 0x73, 0x64,

    0xea, 0xc5, 0xac, 0x83, 0x34, 0xd3, 0xeb, 0xc3, 0xc5, 0x81, 0xa0, 0xff, 0xfa, 0x13, 0x63, 0xeb,
    0x17, 0x0d, 0xdd, 0x51, 0xb7, 0xf0, 0xda, 0x49, 0xd3, 0x16, 0x55, 0x26, 0x29, 0xd4, 0x68, 0x9e,
    0x2b, 0x16, 0xbe, 0x58, 0x7d, 0x47, 0xa1, 0xfc, 0x8f, 0xf8, 0xb8, 0xd1, 0x7a, 0xd0, 0x31, 0xce,
    0x45, 0xcb, 0x3a, 0x8f, 0x95, 0x16, 0x04, 0x28, 0xaf, 0xd7, 0xfb, 0xca, 0xbb, 0x4b, 0x40, 0x7e,
]

PRIME32_1 = 0x9E3779B1;  # /* 0b10011110001101110111100110110001 */
PRIME32_2 = 0x85EBCA77;  # /* 0b10000101111010111100101001110111 */
PRIME32_3 = 0xC2B2AE3D;  # /* 0b11000010101100101010111000111101 */

PRIME64_1 = 0x9E3779B185EBCA87;  # /* 0b1001111000110111011110011011000110000101111010111100101010000111 */
PRIME64_2 = 0xC2B2AE3D27D4EB4F;  # /* 0b1100001010110010101011100011110100100111110101001110101101001111 */
PRIME64_3 = 0x165667B19E3779F9;  # /* 0b0001011001010110011001111011000110011110001101110111100111111001 */
PRIME64_4 = 0x85EBCA77C2B2AE63;  # /* 0b1000010111101011110010100111011111000010101100101010111001100011 */
PRIME64_5 = 0x27D4EB2F165667C5;  # /* 0b0010011111010100111010110010111100010110010101100110011111000101 */

PRIME_MX1 = 0x165667919E3779F9
PRIME_MX2 = 0x9FB21C651E98DF25

def make_u64(alist):
    """
    Same as int.from_bytes(..., 'little')
    """
    return alist[0] | (alist[1] << 8) | (alist[2] << 16) | (alist[3] << 24) | (alist[4] << 32) | (alist[5] << 40) | (alist[6] << 48) | (alist[7] << 56)

def xxh3_acc_512_128(acc, input, secret):
    for i in range(8):
        input_val = make_u64(input[i*8:i*8+8])
        acc[i^1] += input_val
        acc[i^1] = acc[i^1] % 2**64
        input_val ^= make_u64(secret[i*8:i*8+8])
        acc[i] += (input_val >> 32) * (input_val & 0xFFFFFFFF)
        acc[i] = acc[i] % 2**64

def xxh3_acc_128(acc, input, secret, nb_stripes):
    for n in range(nb_stripes):
        xxh3_acc_512_128(acc, input[64*n:64*n+64], secret[8*n:])

def xxh3_scramble_acc(acc, secret):
    for i in range(8):
        acc[i] ^= acc[i] >> 47
        acc[i] ^= make_u64(secret[i*8:i*8+8])
        acc[i] = acc[i] % 2**64
        acc[i] *= PRIME32_1
        acc[i] = acc[i] % 2**64

def xxh3_avalance(hash):
    hash ^= hash >> 37
    hash *= PRIME_MX1
    hash = hash % 2**64
    hash ^= hash >> 32
    return hash

def xxh3_merge_accs(acc, key, start):
    result64 = start
    for i in range(4):
        mulresult = (acc[2*i] ^ make_u64(key[16*i:16*i+8])) * (acc[2*i+1] ^ make_u64(key[16*i+8:16*i+16]))
        result64 = (result64 + ((mulresult >> 64) ^ mulresult)) % 2**64
    return xxh3_avalance(result64)


def xxh3_128_long_with_secret(input, secret):
    nb_rounds = (192 - 64) // 8
    block_len = 64 * nb_rounds
    l_input= len(input) - 1
    nb_blocks = l_input // block_len
    nb_stripes = (l_input - block_len * nb_blocks) // 64
    

    acc = [0] * 8
    acc[0] = PRIME32_3
    acc[1] = PRIME64_1
    acc[2] = PRIME64_2
    acc[3] = PRIME64_3
    acc[4] = PRIME64_4
    acc[5] = PRIME32_2
    acc[6] = PRIME64_5
    acc[7] = PRIME32_1

    for n in range(nb_blocks):
        xxh3_acc_128(acc, input[n*block_len:], secret, nb_rounds)
        xxh3_scramble_acc(acc, secret[128:])
    
    xxh3_acc_128(acc, input[nb_blocks*block_len:], secret, nb_stripes)

    xxh3_acc_512_128(acc, input[-64:], secret[-71:])
    
    hash_low64 = xxh3_merge_accs(acc, secret[11:], (len(input) * PRIME64_1) & 0xFFFFFFFFFFFFFFFF)
    hash_high64 = xxh3_merge_accs(acc, secret[-75:], ~(len(input) * PRIME64_2) & 0xFFFFFFFFFFFFFFFF)

    hash = hash_low64 | (hash_high64 << 64)
    return hash.to_bytes(16, 'big')

def xxh3_128_digest(input, seed=0):
    assert len(input) > 240
    secret = SECRET_DEFAULT[:]
    secret_u64 = [make_u64(secret[i*8:i*8+8]) for i in range(24)]
    for i in range(12):
        secret_u64[2*i] += seed
        secret_u64[2*i+1] -= seed
    secret = [] 
    for i in range(24):
        secret += (secret_u64[i] % 2**64).to_bytes(8, 'little')
    return xxh3_128_long_with_secret(input, secret)

if __name__ == "__main__":
    s = os.urandom(1021)
    seed = int.from_bytes(os.urandom(8), 'little')
    import xxhash
    assert xxhash.xxh3_128(s, seed=seed).digest() == xxh3_128_digest(s, seed=seed)

