import os
from polynomial import fast_polynomial_gcd
from random import shuffle, choices
from tqdm import tqdm

def flatter(M):
    from subprocess import check_output
    from re import findall
    z = "[[" + "]\n[".join(" ".join(map(str, row)) for row in M) + "]]"
    ret = check_output(["flatter"], input=z.encode())
    return matrix(M.nrows(), M.ncols(), map(int, findall(b"-?\\d+", ret)))

orig_samples = []

with open("output.txt", "r") as f:
    p, a, b = map(int, f.readline().strip().split())
    EC = EllipticCurve(GF(p), [a, b])
    # print(p, a, b)
    for _ in range(1000):
        a, out = map(int, f.readline().strip().split())
        orig_samples.append((a, out))


import json, sys

with open("good_samples.json", "r") as f:
    good_samples = json.load(f)

order = EC.cardinality()

def small_relation(alist):
    M = []
    M.append([order]+[0]*len(alist))
    k = 54
    for i in range(len(alist)):
        v = [alist[i]]+[0]*len(alist)
        v[i+1] = 2**k
        M.append(v)
    M = matrix(ZZ, M)
    M = M.LLL()
    # M = M.change_ring(QQ)
    # for i in range(len(alist)):
    #     M.rescale_col(i+1, 1/2**k)
    # print(M)
    # print(ZZ(abs(M[0][0])).bit_length())
    # print(ZZ(abs(M[1][0])).bit_length())
    return abs(M[0][0])

index = int(sys.argv[1])

alist = [a for a, _ in orig_samples]


# good_a = []
# k = 26
# # small_relation([a for a, _ in choices(orig_samples, k=3)])
# if index!=0:
#     pbar = range(2**k*index, 2**k*index+2**k)
# else:
#     pbar = tqdm(range(2**k))
# for i in pbar:
#     if i%(1<<20)==0:
#         print(index, hex(i-2**k*index))
#     ii, t0 = divmod(i, 512)
#     ii, t1 = divmod(ii, 512)
#     t3, t2 = divmod(ii, 256)
#     t2 += 512
#     t3 += 768
#     if t0>=t1:
#         continue
#     ass = [alist[t0], alist[t1], alist[t2], alist[t3]]
#     b = small_relation(ass)
#     if b.bit_length()<=58:
#         good_a.append((b, i))
#     if len(good_a) >= 2**21:
#         save(good_a, f"outputs/lll_{index}_{i}.sobj")
#         good_a = []

# os.makedirs("outputs", exist_ok=True)
# print(len(good_a))
# save(good_a, f"outputs/lll_{index}.sobj")


for _ in tqdm(range(65536)):
    shuffle(orig_samples)
    samples = orig_samples[:16]

    alist = [a for a, _ in samples]

    M = matrix(ZZ, len(samples), len(samples))
    M[0] = vector(ZZ,[order]+[0]*(len(samples)-1))
    for i in range(1, len(samples)):
        v = [0]*len(samples)
        v[i] = 1
        v[0] = (-alist[i]*pow(alist[0], -1, order)) % order
        M[i] = vector(ZZ, v)

    va = vector(ZZ, alist)

    # M = flatter(M)
    M = M.BKZ()
    # print(M[0])

    cnts = []
    for j in range(len(samples)):
        cnt = 0
        for i in range(len(samples)):
            if M[j, i] != 0:
                cnt += 1
        if cnt<=9:
            print(j, M[j], sum(abs(M[j, i]) for i in range(len(samples))))
            v = list(M[j])
            good_samples.append([samples, [int(x) for x in v]])


with open("good_samples.json", "w") as f:
    json.dump(good_samples, f)