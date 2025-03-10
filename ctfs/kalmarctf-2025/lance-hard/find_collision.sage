import os
from random import shuffle
import json

orig_samples = []

with open("output.txt", "r") as f:
    p, a, b = map(int, f.readline().strip().split())
    EC = EllipticCurve(GF(p), [a, b])
    # print(p, a, b)
    for _ in range(1000):
        a, out = map(int, f.readline().strip().split())
        orig_samples.append((a, out))

order = EC.order()

def get_idx(i):
    ii, t0 = divmod(i, 512)
    ii, t1 = divmod(ii, 512)
    t3, t2 = divmod(ii, 256)
    t2 += 512
    t3 += 768
    return [t0, t1, t2, t3]

def solve_relations(idxs):
    alist = [orig_samples[i][0] for i in idxs]
    M = matrix(ZZ, len(idxs), len(idxs))
    M[0] = vector(ZZ,[order]+[0]*(len(idxs)-1))
    for i in range(1, len(idxs)):
        v = [0]*len(idxs)
        v[i] = 1
        v[0] = (-alist[i]*pow(alist[0], -1, order)) % order
        M[i] = vector(ZZ, v)
    M = M.LLL()
    print(M)
    v = M[0]
    ss = []
    for i, val in zip(idxs, v):
        a, out = orig_samples[i]
        if val < 0:
            a = -a
            val = -val
        ss.append((a, out, val))
    print(ss)
    
    

solve_relations([323, 452, 805, 549, 771, 501, 214, 537])


datas = {}
files = os.listdir("outputs")
shuffle(files)
for f in files:
    if not f.endswith(".sobj"):
        continue
    print(f, len(datas), len(datas).bit_length())
    good_a = load(f"outputs/{f}")
    for k, v in good_a:
        if k in datas:
            v2 = datas[k]
            idx_list = get_idx(v) + get_idx(v2)
            idx_list = list(set(idx_list))
            if len((idx_list)) < 7:
                continue
            print(idx_list)
            solve_relations(idx_list)
        else:
            datas[k] = v

print(len(datas))