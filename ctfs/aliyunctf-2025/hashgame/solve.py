import zlib
from sage.all import *
import string

charset = string.ascii_letters + string.digits
charset = charset.encode()

# Array ( [0] => 66c73085 [1] => 87a2e347 [2] => 4dfb3966 [3] => a8d7d476 [4] => 01cfc2fc [5] => 8e4da93b [6] => 12027cda [7] => dca596aa [8] => 3bf6e392 [9] => 13d1b90c [10] => 87c29443 [11] => 4d4b0264 [12] => a80fc977 [13] => 01234cfc [14] => 8e3bee3b [15] => 12b95fda [16] => 5c7887aa [17] => fb18eb92 [18] => 73a6bd0c [19] => 37f99643 [20] => 95560364 [21] => 4481c977 [22] => 77644cfc [23] => 3518ee3b [24] => 14263f58 [25] => df37b7eb [26] => e1b11330 [27] => fef2c15d [28] => aa5d48e9 [29] => 008a0cb3 [30] => d5e12e9e [31] => e45adf0a [32] => a709c7c2 [33] => ddaeab24 [34] => 60fd9d57 [35] => 655a66ec [36] => 3c07fb33 [37] => 4b2755de [38] => abb9e22a [39] => db76b950 [40] => 6391946d [41] => bf620273 [42] => 511b497c [43] => a6a7ec7b [44] => 06f75efa [45] => 56df87ba [46] => 7e4beb9a [47] => 6a01dd8a [48] => 6024c682 [49] => e5b6cb86 [50] => 7cf1ad06 [51] => 6b5cfec4 [52] => 3b04b727 [53] => 13a81356 [54] => 07fec16e [55] => 0dd5a872 [56] => 88409c7c [57] => 9184e6f9 [58] => 46683b39 [59] => f61035db [60] => ae2c32aa [61] => 82b2b192 [62] => 947df08e [63] => 1f9ad080 [64] => 0167a005 [65] => 8e191847 [66] => 12a824e4 [67] => dcf0bab5 [68] => bbdc759d [69] => 53c4720b [70] => 27487140 [71] => 1d8ef065 [72] => 006d3077 [73] => 559230fc [74] => 2463d03b [75] => 479540da [76] => ad60e828 [77] => 581abc51 [78] => f9a976ef [79] => f27e7332 [80] => ac1b91de [81] => 0329e0a8 [82] => 8f3eb811 [83] => 4935144d [84] => aa304263 [85] => 80bc09f6 [86] => 957aacbc [87] => 44179e1b [88] => 77af67ca [89] => b5fdfb20 [90] => d4d4b555 [91] => bf4e72ed [92] => 510d7133 [93] => a6ac705c [94] => 86f290e9 [95] => 96dd60b3 [96] => 1eca189e [97] => dac1a488 [98] => 38c4fa83 [99] => c9c65586 [100] => 6ac9e206 [101] => 60c0d9c4 [102] => e544c4a5 [103] => 7c082a17 [104] => eba03dcc [105] => 7bfad623 [106] => 33572354 [107] => 9781d96f [108] => c5ea2472 [109] => 6c5fda7c [110] => 638bc5f9 [111] => bfef2a39 [112] => d15d5d59 [113] => e6846669 [114] => a6e61bf3 [115] => 865725be [116] => 160fba98 [117] => 5ea3f58b [118] => 7a755282 [119] => 689e8186 [120] => e16be884 )
array1 = [
    "66c73085", "87a2e347", "4dfb3966", "a8d7d476", "01cfc2fc", "8e4da93b", "12027cda", "dca596aa", "3bf6e392", "13d1b90c",
    "87c29443", "4d4b0264", "a80fc977", "01234cfc", "8e3bee3b", "12b95fda", "5c7887aa", "fb18eb92", "73a6bd0c", "37f99643",
    "95560364", "4481c977", "77644cfc", "3518ee3b", "14263f58", "df37b7eb", "e1b11330", "fef2c15d", "aa5d48e9", "008a0cb3",
    "d5e12e9e", "e45adf0a", "a709c7c2", "ddaeab24", "60fd9d57", "655a66ec", "3c07fb33", "4b2755de", "abb9e22a", "db76b950",
    "6391946d", "bf620273", "511b497c", "a6a7ec7b", "06f75efa", "56df87ba", "7e4beb9a", "6a01dd8a", "6024c682", "e5b6cb86",
    "7cf1ad06", "6b5cfec4", "3b04b727", "13a81356", "07fec16e", "0dd5a872", "88409c7c", "9184e6f9", "46683b39", "f61035db",
    "ae2c32aa", "82b2b192", "947df08e", "1f9ad080", "0167a005", "8e191847", "12a824e4", "dcf0bab5", "bbdc759d", "53c4720b",
    "27487140", "1d8ef065", "006d3077", "559230fc", "2463d03b", "479540da", "ad60e828", "581abc51", "f9a976ef", "f27e7332",
    "ac1b91de", "0329e0a8", "8f3eb811", "4935144d", "aa304263", "80bc09f6", "957aacbc", "44179e1b", "77af67ca", "b5fdfb20",
    "d4d4b555", "bf4e72ed", "510d7133", "a6ac705c", "86f290e9", "96dd60b3", "1eca189e", "dac1a488", "38c4fa83", "c9c65586",
    "6ac9e206", "60c0d9c4", "e544c4a5", "7c082a17", "eba03dcc", "7bfad623", "33572354", "9781d96f", "c5ea2472", "6c5fda7c",
    "638bc5f9", "bfef2a39", "d15d5d59", "e6846669", "a6e61bf3", "865725be", "160fba98", "5ea3f58b", "7a755282", "689e8186",
    "e16be884"
]

# Array ( [0] => 1d66fb6a [1] => a7ea3082 [2] => 40209e9e [3] => 33c5c990 [4] => 0a376217 [5] => fb76b4f4 [6] => 6e6edca5 [7] => c95a6bad [8] => 9ac03029 [9] => 419b169e [10] => 33180d90 [11] => 0a598017 [12] => fb41c5f4 [13] => 6e756425 [14] => c957b7ed [15] => 9ac6de09 [16] => b30e6afb [17] => 53e10bd1 [18] => d79d8017 [19] => 95a3c5f4 [20] => 59046425 [21] => d2ef37ed [22] => 971a9e09 [23] => b5e04afb [24] => a49d2082 [25] => 9e151488 [26] => 5cdf0c9b [27] => d00283b2 [28] => 7bd4c706 [29] => 2e3fe55c [30] => 04ca7471 [31] => fc083fc7 [32] => 80691a1c [33] => bd0cde7d [34] => a0eb6ac1 [35] => ae18b09f [36] => a9615db0 [37] => 47652807 [38] => dddf91fc [39] => 7d3a4e21 [40] => c0f022ef [41] => 7da1948a [42] => 2d054c9a [43] => 05572092 [44] => 117e1696 [45] => 1b6a8d94 [46] => 1e60c015 [47] => f15d65f5 [48] => 86c3b705 [49] => 6a87cef5 [50] => cb2ee285 [51] => 9bfa74bd [52] => b3903fa1 [53] => a7a51a2f [54] => adbf88e8 [55] => 450a42ab [56] => dce824aa [57] => fb63f26b [58] => 83dcfcca [59] => 523bf8ba [60] => 3ac87a82 [61] => 0eb1bb9e [62] => 148d5b10 [63] => 19932b57 [64] => f2a49054 [65] => 7b33fb25 [66] => c3f4f86d [67] => 9f9779c9 [68] => b1a6b91b [69] => a6be5972 [70] => 408aaa66 [71] => 3390d3ec [72] => 0a1def29 [73] => 4e5d7eb0 [74] => 34fb3987 [75] => e410993c [76] => 61ddca41 [77] => ce83e0df [78] => 992cf590 [79] => 5f43fc17 [80] => d1ccfbf4 [81] => 95701198 [82] => 596d8e13 [83] => d2dbc2f6 [84] => 7ab867a4 [85] => 2e89b50d [86] => e929df79 [87] => 8af9ea43 [88] => bb11f0de [89] => 03d6efb2 [90] => 123ef106 [91] => 1acafe5c [92] => 1eb0f9f1 [93] => f1357907 [94] => 86f7b97c [95] => 50ae5a61 [96] => d63a28cf [97] => ac804bf8 [98] => 4595a323 [99] => dca7d46e [100] => 7d866ce8 [101] => 2d16b0ab [102] => e8e65daa [103] => 67a6a80a [104] => 2006d2da [105] => f03f4d51 [106] => 8672a357 [107] => bd545454 [108] => 4d7facf5 [109] => d8d2d385 [110] => 92046c3d [111] => b76f33e1 [112] => a5da9c0f [113] => fc53e0ea [114] => 6dfc76aa [115] => 252bbd8a [116] => 0140581a [117] => 1375aad2 [118] => 1a6f53b6 [119] => 1ee22f04 [120] => 1ca4915d )
array2 = [
    "1d66fb6a", "a7ea3082", "40209e9e", "33c5c990", "0a376217", "fb76b4f4", "6e6edca5", "c95a6bad", "9ac03029", "419b169e",
    "33180d90", "0a598017", "fb41c5f4", "6e756425", "c957b7ed", "9ac6de09", "b30e6afb", "53e10bd1", "d79d8017", "95a3c5f4",
    "59046425", "d2ef37ed", "971a9e09", "b5e04afb", "a49d2082", "9e151488", "5cdf0c9b", "d00283b2", "7bd4c706", "2e3fe55c",
    "04ca7471", "fc083fc7", "80691a1c", "bd0cde7d", "a0eb6ac1", "ae18b09f", "a9615db0", "47652807", "dddf91fc", "7d3a4e21",
    "c0f022ef", "7da1948a", "2d054c9a", "05572092", "117e1696", "1b6a8d94", "1e60c015", "f15d65f5", "86c3b705", "6a87cef5",
    "cb2ee285", "9bfa74bd", "b3903fa1", "a7a51a2f", "adbf88e8", "450a42ab", "dce824aa", "fb63f26b", "83dcfcca", "523bf8ba",
    "3ac87a82", "0eb1bb9e", "148d5b10", "19932b57", "f2a49054", "7b33fb25", "c3f4f86d", "9f9779c9", "b1a6b91b", "a6be5972",
    "408aaa66", "3390d3ec", "0a1def29", "4e5d7eb0", "34fb3987", "e410993c", "61ddca41", "ce83e0df", "992cf590", "5f43fc17",
    "d1ccfbf4", "95701198", "596d8e13", "d2dbc2f6", "7ab867a4", "2e89b50d", "e929df79", "8af9ea43", "bb11f0de", "03d6efb2",
    "123ef106", "1acafe5c", "1eb0f9f1", "f1357907", "86f7b97c", "50ae5a61", "d63a28cf", "ac804bf8", "4595a323", "dca7d46e",
    "7d866ce8", "2d16b0ab", "e8e65daa", "67a6a80a", "2006d2da", "f03f4d51", "8672a357", "bd545454", "4d7facf5", "d8d2d385",
    "92046c3d", "b76f33e1", "a5da9c0f", "fc53e0ea", "6dfc76aa", "252bbd8a", "0140581a", "1375aad2", "1a6f53b6", "1ee22f04",
    "1ca4915d"
]

# Array ( [0] => 1cb06443 [1] => 65b662bc [2] => a2c55c44 [3] => c17cc338 [4] => f0a00c86 [5] => e84e6b59 [6] => 66cf63ce [7] => a379dcfd [8] => 4354b81c [9] => ad8121bb [10] => 4428c6bf [11] => 30fc353d [12] => 0a964cfc [13] => 95554b64 [14] => dab4c8a8 [15] => fd44094e [16] => eebc69bd [17] => 36b3cee0 [18] => 8b478a6a [19] => d5bda82f [20] => 78368275 [21] => 2ef31758 [22] => 8767e6b6 [23] => d3ad9e41 [24] => 7b3e9942 [25] => 862f4309 [26] => 51fff7e6 [27] => b8e196e9 [28] => 4e989d16 [29] => b7522391 [30] => 494147aa [31] => b4bececf [32] => 48b73105 [33] => 04088e5b [34] => 10ec114f [35] => 1a9e5ec5 [36] => 1fa77900 [37] => 9fcdd19a [38] => dff885d7 [39] => 7d141489 [40] => 2c625c26 [41] => d5fea4db [42] => 7817040f [43] => 2ee3d465 [44] => 0599bc50 [45] => 92d2b332 [46] => d9773483 [47] => 7e53cc23 [48] => 2dc1b073 [49] => fbed62e9 [50] => 6f1ee716 [51] => a7911e91 [52] => 4120d92a [53] => b08e018f [54] => 4aaf56a5 [55] => 37bffd30 [56] => 8bc19382 [57] => 66af0f67 [58] => 21bfd1d1 [59] => 0237be8a [60] => 9105b25f [61] => 5a6a8f4d [62] => 3fdd11c4 [63] => 8ff0e5f8 [64] => d7e61fe6 [65] => bad861a8 [66] => cd725dce [67] => f6a743fd [68] => 69bbf79c [69] => a4c396d4 [70] => c27fa670 [71] => f121be22 [72] => e88eb20b [73] => 28b1f227 [74] => 06b0af71 [75] => 11b001da [76] => 98c66df7 [77] => 5e8b6099 [78] => 3dade62e [79] => 8ec89e0d [80] => 558c1964 [81] => e9de6ab7 [82] => 66076339 [83] => 21ebe7fe [84] => 80eb9ee5 [85] => 529d9910 [86] => b950a192 [87] => ccb63dd3 [88] => 74b3488b [89] => 00b8d395 [90] => 12b43fa8 [91] => 994472ce [92] => dcbc547d [93] => 7cb67c5c [94] => ae455334 [95] => c73cc480 [96] => f3800f5a [97] => 7212b11f [98] => 2be10eed [99] => 0718d114 [100] => 93920590 [101] => d9d76fd2 [102] => fcf5daf3 [103] => 6c92bb1b [104] => 24a10bef [105] => 4e10ad7c [106] => b7163ba4 [107] => cb9570c8 [108] => f5d4d57e [109] => eaf407a5 [110] => 679255b0 [111] => a3d747c2 [112] => c1f5cefb [113] => 97971300 [114] => dbd5e49a [115] => fdf49f57 [116] => 6c1219c9 [117] => 24e15a86 [118] => 826ec059 [119] => 53df364e [120] => b9f1f63d )
array3 = [
    "1cb06443", "65b662bc", "a2c55c44", "c17cc338", "f0a00c86", "e84e6b59", "66cf63ce", "a379dcfd", "4354b81c", "ad8121bb",
    "4428c6bf", "30fc353d", "0a964cfc", "95554b64", "dab4c8a8", "fd44094e", "eebc69bd", "36b3cee0", "8b478a6a", "d5bda82f",
    "78368275", "2ef31758", "8767e6b6", "d3ad9e41", "7b3e9942", "862f4309", "51fff7e6", "b8e196e9", "4e989d16", "b7522391",
    "494147aa", "b4bececf", "48b73105", "04088e5b", "10ec114f", "1a9e5ec5", "1fa77900", "9fcdd19a", "dff885d7", "7d141489",
    "2c625c26", "d5fea4db", "7817040f", "2ee3d465", "0599bc50", "92d2b332", "d9773483", "7e53cc23", "2dc1b073", "fbed62e9",
    "6f1ee716", "a7911e91", "4120d92a", "b08e018f", "4aaf56a5", "37bffd30", "8bc19382", "66af0f67", "21bfd1d1", "0237be8a",
    "9105b25f", "5a6a8f4d", "3fdd11c4", "8ff0e5f8", "d7e61fe6", "bad861a8", "cd725dce", "f6a743fd", "69bbf79c", "a4c396d4",
    "c27fa670", "f121be22", "e88eb20b", "28b1f227", "06b0af71", "11b001da", "98c66df7", "5e8b6099", "3dade62e", "8ec89e0d",
    "558c1964", "e9de6ab7", "66076339", "21ebe7fe", "80eb9ee5", "529d9910", "b950a192", "ccb63dd3", "74b3488b", "00b8d395",
    "12b43fa8", "994472ce", "dcbc547d", "7cb67c5c", "ae455334", "c73cc480", "f3800f5a", "7212b11f", "2be10eed", "0718d114",
    "93920590", "d9d76fd2", "fcf5daf3", "6c92bb1b", "24a10bef", "4e10ad7c", "b7163ba4", "cb9570c8", "f5d4d57e", "eaf407a5",
    "679255b0", "a3d747c2", "c1f5cefb", "97971300", "dbd5e49a", "fdf49f57", "6c1219c9", "24e15a86", "826ec059", "53df364e",
    "b9f1f63d"
]

array1 = [int(i, 16) for i in array1]
array2 = [int(i, 16) for i in array2]
array3 = [int(i, 16) for i in array3]

base1 = array1.pop(0)
base2 = array2.pop(0)
base3 = array3.pop(0)

def to_bits(n):
    b = []
    for i in range(32):
        if n & (1 << i):
            b.append(1)
        else:
            b.append(0)
    return b

def bytes_to_bits(b_str, num_bit=8):
    b = []
    for s in b_str:
        for i in range(num_bit):
            if s & (1 << (num_bit-1-i)):
                b.append(1)
            else:
                b.append(0)
    return b

M = []

for i in range(120):
    if i % 8 != 0:
        M.append(to_bits(array1[i] ^ base1) + to_bits(array2[i] ^ base2) + to_bits(array3[i] ^ base3))

# print(to_bits((zlib.crc32(b"aliyunctf{ZnrcjAXhK3WgwiC}\n") & 0xffffffff)^base2))

target1 = 0xf70050ea ^ base1
target2 = 0xa92254ab ^ base2
target3 = 0x9b495df9 ^ base3

target_vector = vector(GF(2), to_bits(target1) + to_bits(target2) + to_bits(target3))


def bits_to_bytes(v):
    l = len(v) // 7
    b = b""
    for i in range(l):
        c = 0
        for j in range(7):
            c |= int(v[i*7+j]) << (6-j)
        b += bytes([c])
    return b


M = Matrix(GF(2), M)

# v = vector(GF(2), bytes_to_bits(b"ZnrcjAXhK3WgwiC", num_bit=7))


# print(target_vector)
# print(v*M)

M1 = M[:14]
M2 = M[14:]


for s0 in charset:
    for s1 in charset:
        v1 = vector(GF(2), bytes_to_bits(bytes([s0,s1]), num_bit=7))
        try:
            v2 = M2.solve_left(target_vector - v1*M1)
        except ValueError:
            continue
        s2 = bits_to_bytes(v2.list())
        find = True
        for s in s2:
            if s not in charset:
                find = False
                break
        if find:
            print(bytes([s0,s1]) + s2)










