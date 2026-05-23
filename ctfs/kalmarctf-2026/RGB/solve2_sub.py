from sage.all import *
from sage.rings.generic import ProductTree
from tqdm import tqdm, trange
import json
import sys
load("composed_prod.pyx")

p = 110878580464934402421519766750253673622313
q = 142494346453810376391409508907483524822863
N = p * q

proc_id = int(sys.argv[1])
start = int(sys.argv[2])
end = int(sys.argv[3])
p, v, ers = json.loads(input())

print(f"Subprocess {proc_id}: start={start}, end={end}")

F = GF(p)
R = PolynomialRing(F, "x")
z0 = (1337-N)//2
s = z0 * v[1] % (p-1)
ervs_pos = []
ervs_neg = []
for i in range(9):
    e, r = ers[i]
    s = (s + e * v[i+2]) % (p-1)
    if v[i+2] == 0:
        continue
    if v[i+2] > 0:
        ervs_pos.append((e, v[i+2], r))
    else:
        ervs_neg.append((e, abs(v[i+2]), r))
s = s % (p-1)
assert s == 0, s
assert len(ervs_pos) == 4 and len(ervs_neg) == 4

p_int = int(p)
ervs_pos_cython =[(int(e), int(v), int(r)) for e, v, r in ervs_pos]
ervs_neg_cython =[(int(e), int(v), int(r)) for e, v, r in ervs_neg]
abs_v1_cython = int(abs(v[1]))
is_v1_neg_cython = bool(v[1] < 0)

def compute_y(zi):
    return compute_y_cython(
        int(zi),
        ervs_pos_cython,
        ervs_neg_cython,
        abs_v1_cython,
        is_v1_neg_cython,
        p_int,
        R
    )

import time
start_time = time.time()

ys = []
for zi in range(start, end):
    y = compute_y(zi)
    ys.append(int(y))
    if (zi - start) % 2**15 == 0 and zi > start:
        print(f"Subprocess {proc_id}: Computed {zi - start} zi, time elapsed: {time.time() - start_time:.2f} seconds, estimated time remaining: {(end - zi) * (time.time() - start_time) / ((zi - start) + 1):.2f} seconds")

save(ys, f"output/ys_{proc_id}.sobj")




