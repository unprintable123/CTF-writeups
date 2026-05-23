from sage.all import *
from ast import literal_eval
import heapq

p = 110878580464934402421519766750253673622313
q = 142494346453810376391409508907483524822863
N = p * q
assert N == 15799570859077053940492342195534009129029031475644902333347360612140434908889342119

data = []

with open("output.txt") as f:
    assert N == literal_eval(f.readline().strip().split(" = ")[1])
    f.readline()
    for _ in range(136):
        e = int(f.readline().strip().split("e = ")[1])
        e = (e * 3 + 1337) % N
        r = int(f.readline().strip())
        # assert r == pow(13, e, N) + pow(13, (e * 3 + 1337) % N, N)
        if not ((e * 3 + 1337) > N and (e * 3 + 1337) < 2*N):
            continue
        e = (e+(1337-N)//2)
        # z0 = pow(13, (1337-N)//2, N)
        # assert r * z0 % N == (pow(13, e, N) + pow(13, 3 * e, N)) % N
        data.append((e, r))

print(len(data))
class TopKStore:
    def __init__(self, k):
        self.k = k
        self.heap = []

    def add(self, score, item):
        entry = (score, item)
        
        if len(self.heap) < self.k:
            heapq.heappush(self.heap, entry)
        elif score > self.heap[0][0]:
            heapq.heapreplace(self.heap, entry)

    def results(self):
        return sorted(self.heap, key=lambda x: x[0], reverse=True)
best_candidates_p = TopKStore(100)
best_candidates_q = TopKStore(100)

import tqdm, random
def update(p, best_candidates):
    for _ in tqdm.tqdm(range(100000)):
        random.shuffle(data)
        k = 9
        es = [e for e, r in data[:k]]
        M = identity_matrix(QQ, k+2)
        M[0] = vector(ZZ, [p-1]+[(1337-N)//2]+es)

        M = M.transpose()
        M.rescale_col(0, 2**16)
        M = M.LLL()
        v = M[0]
        
        if v.hamming_weight() > 9:
            continue
        
        v1 = v[1]
        u1, u2 = 0, 0
        cnt = 0
        for rr in v[2:]:
            if rr > 0:
                cnt += 1
                u1 += rr
            else:
                u2 += abs(rr)
        if cnt != 4:
            continue
        u1 += abs(v1) * 3
        u2 += abs(v1) * 3
        score = max(u1, u2, abs(v1) * 9) * 3**(v.hamming_weight()-2)
        score = int(score)
        best_candidates.add(-score, ([int(v0) for v0 in v.list()], data[:k]))


def save():
    with open("candidates_p.json", "w") as f:
        import json
        json.dump(best_candidates_p.results(), f)

    with open("candidates_q.json", "w") as f:
        import json
        json.dump(best_candidates_q.results(), f)
    
    # test
    _, item=best_candidates_q.results()[0]
    v, data_subset = item
    z0 = (1337-N)//2
    s = z0 * v[1] % (q-1)
    for i in range(9):
        e, r = data_subset[i]
        s = (s + e * v[i+2]) % (q-1)
    s = s % (q-1)
    assert s == 0

while True:
    update(p, best_candidates_p)
    update(q, best_candidates_q)
    save()
