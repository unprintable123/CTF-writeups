import json
from sage.all import *

def flatter(M):
    from subprocess import check_output
    from re import findall
    z = "[[" + "]\n[".join(" ".join(map(str, row)) for row in M) + "]]"
    ret = check_output(["flatter"], input=z.encode())
    return matrix(M.nrows(), M.ncols(), map(int, findall(b"-?\\d+", ret)))

with open('outputs.json', 'r') as f:
    outputs = json.load(f)
with open('real_output.json', 'r') as f:
    real_output = json.load(f)
with open('zero_output.json', 'r') as f:
    zero_output = json.load(f)
with open('ciphertext.txt', 'r') as f:
    ciphertexts = f.readlines()
    real_output = []
    cs = []
    for c in ciphertexts:
        if len(c) < 10:
            continue
        nums = c.strip().split()
        cs.append([float(i) for i in nums])
        real_output.extend([float(i) for i in nums])

        


ids = []
for i in range(432):
    if i % 9 == 0 or i % 9 == 1:
        continue
    ids.append(i)

outputs = [outputs[i] for i in ids]

outputs = matrix(ZZ, outputs)

real_output = vector(ZZ, real_output)
zero_output = vector(ZZ, zero_output)
real_output = real_output - zero_output

# flag='SUCTF{xxxxxxxxxxx?xxxxxxxxxxxxxxxxxxxxxxxxxxxxx}'
# flag_list=[]
# flag_ord = []
# for i in flag:
#     binary_str = format(ord(i), '07b')
#     # print(binary_str)
#     flag_ord.append(int(binary_str[::-1],2))
#     for bit in binary_str:
#         flag_list.append(int(bit))

# flag_ord = vector(ZZ, flag_ord)


# flag_list = vector(ZZ, flag_list)

# assert flag_list * outputs == real_output

v = outputs.solve_left(real_output)

M = block_matrix(ZZ, [[matrix([real_output]), matrix([[0]*(48*7)]), vector([1024])], [-outputs, identity_matrix(48*7,48*7), zero_matrix(ZZ, 48*7, 1)]])

# f3 = vector(ZZ, [-1]+list(flag_list))
# print(f3*M)

# M = flatter(M)
# save(M, 'M.sobj')

basis = []
target = None

M = load('M.sobj')
for i in range(336):
    if M[i][-1] != 0:
        target = M[i,49*49:]
        break
    v = M[i]
    if v.norm() < 50:
        basis.append(v[49*49:])

print(target)

graph = {}

for b in basis:
    non_zero = b.nonzero_positions()
    i0, i1 = non_zero
    if abs(b[i0]) > abs(b[i1]):
        i0, i1 = i1, i0
    if abs(b[i1]) ==2:
        graph[i1] = i0

print(graph)
target = target[0]

flag = True
while flag:
    flag = False
    for i in range(336):
        if target[i] < 0:
            next_i = graph[i]
            z_v = [0] * 337
            z_v[i] = 2
            z_v[next_i] = -1
            z_v = vector(ZZ, z_v)
            target = target + z_v
            flag = True
            break

    print(target)

target = target[:-1]
flag_bits = list(target)
print(flag_bits)

for i in range(48):
    def get_byte(i):
        return int(''.join(str(flag_bits[i*7+j]) for j in range(7)), 2)
    print(chr(get_byte(i)), end='')

print()




