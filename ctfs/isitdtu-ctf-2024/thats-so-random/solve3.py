import os
import json

os.chdir(os.path.dirname(os.path.abspath(__file__)))

with open("pairing.txt") as f:
    data = json.load(f)

vertices = set()
for pair in data:
    for i in range(3):
        vertices.add(pair[i])

state_idx = [None] * (max(vertices)+1)
state_idx[0] = 0

raw_data = data[:]

# 0 396 623

def set_idx(idx, val):
    if state_idx[idx] is None:
        state_idx[idx] = val
    else:
        assert state_idx[idx] == val

for i in range(10000):
    if i % 100 == 0:
        print(i)
    for pair in data:
        if state_idx[pair[0]] is not None:
            set_idx(pair[1], state_idx[pair[0]] + 396)
            set_idx(pair[2], state_idx[pair[0]] + 623)
        if state_idx[pair[1]] is not None:
            set_idx(pair[0], state_idx[pair[1]] - 396)
            set_idx(pair[2], state_idx[pair[1]] + 623 - 396)
        if state_idx[pair[2]] is not None:
            set_idx(pair[0], state_idx[pair[2]] - 623)
            set_idx(pair[1], state_idx[pair[2]] - 623 + 396)
    newdata = []
    for pair in data:
        if state_idx[pair[0]] is None or state_idx[pair[1]] is None or state_idx[pair[2]] is None:
            newdata.append(pair)
    data = newdata

# with open("idx_map.txt", "w") as f:
#     f.write(json.dumps(state_idx))


