from sage.all import *
from pwn import *
from tqdm import tqdm
from collections import Counter

io = process(['python3', 'chall3.py'])
# io = remote('apes.chals.sekai.team', 1337, ssl=True)

F = GF(2**8, 'a')
a = F.gen()

perm1 = []
for i in range(256):
    x = F.from_integer(i)
    y = a * x
    perm1.append(y.to_integer())
perm1[0], perm1[1], perm1[255] = perm1[1], perm1[255], perm1[0]

attempts = 0
def fail():
    global attempts
    attempts += 1
    io.sendline(b'00')
    io.recvuntil(b'Bad luck, try again.')

def try_solve():
    io.sendlineafter(b'Plainperm: ', bytes(perm1).hex().encode())
    io.recvuntil(b'Cipherperm: ')
    cipherperm = bytes.fromhex(io.recvline().strip().decode())
    cipherperm_F = [F.from_integer(x) for x in cipherperm]

    cipherperm_F = [x / (a**63) for x in cipherperm_F]
    for b in range(257):
        assert b < 256, "This should not happen"
        b0 = F.from_integer(b)
        cipherperm_F2 = [(x+b0).to_integer()+1 for x in cipherperm_F]
        if len(Permutation(cipherperm_F2).fixed_points()) > 20:
            break
    
    perm2 = Permutation(cipherperm_F2)
    cycles = perm2.cycle_tuples()
    cycles = [cycle for cycle in cycles if len(cycle) > 1]
    u = sum([(len(cycle)-1)//2 for cycle in cycles])
    
    if u != 63 or max([len(cycle) for cycle in cycles]) > 51:
        fail()
        return False
    
    cycles = [tuple(F.from_integer(x-1) for x in cycle) for cycle in cycles]
    print(([len(cycle) for cycle in cycles]), u)

    all_numbers = [F.from_integer(i) for i in range(256)]
    possible_k0 = [all_numbers[:] for _ in range(63)]
    
    def check(us):
        for cycle in cycles:
            if all(u in cycle for u in us):
                inds = [cycle.index(u) for u in us]
                inversions = 0
                if inds[0] > inds[1]: inversions += 1
                if inds[0] > inds[2]: inversions += 1
                if inds[1] > inds[2]: inversions += 1
                if inversions % 2 == 1:
                    return False
                return True
        return False
    
    for i in range(63):
        filtered = []
        a0 = a ** i
        ts = [F.from_integer(t)/a0 for t in [0, 1, 255]]
        
        for k0 in possible_k0[i]:
            us = [u + k0 for u in ts]
            if check(us):
                filtered.append(k0)
        
        possible_k0[i] = filtered

    def update():
        all_pos = sum([list(cycle) for cycle in cycles], [])
        c = {pos: [] for pos in all_pos}

        for i in range(63):
            a0 = a ** i
            ts = [F.from_integer(t)/a0 for t in [0, 1, 255]]
            for k0 in possible_k0[i]:
                us = [u + k0 for u in ts]
                for u in us:
                    c[u].append((i, k0))
        
        for pos in c:
            if len(c[pos]) == 1:
                i, k0 = c[pos][0]
                possible_k0[i] = [k0]
    
    for _ in range(16):
        update()
    
    if prod([len(x) for x in possible_k0]) > 2**14:
        fail()
        return False

    print(attempts)
    print([len(x) for x in possible_k0], prod([len(x) for x in possible_k0]).bit_length())

    possible_maps = [[] for _ in range(63)]
    for i in range(63):
        a0 = a ** i
        ts = [F.from_integer(t)/a0 for t in [0, 1, 255]]
        for k0 in possible_k0[i]:
            us = [u + k0 for u in ts]
            us = [x.to_integer() + 1 for x in us]
            perm3 = Permutation([tuple(us)])
            possible_maps[i].append((k0, perm3))

    def search(cur_map, i):
        if i == 63:
            if cur_map == perm2:
                return [[]]
            else:
                return None
        
        all_results = []
        for k0, perm3 in possible_maps[i]:
            new_map = cur_map * perm3
            result = search(new_map, i + 1)
            if result is not None:
                for r in result:
                    all_results.append([k0] + r)
        
        if all_results:
            return all_results
        
        return None
    
    pathes = search(cur_map=Permutation(list(range(1, 257))), i=0)
    if pathes is None or len(pathes) == 0:
        fail()
        return False
    
    print(len(pathes), pathes)
    path = pathes[0]

    real_ks = []
    a0 = 1
    c0 = 0
    for i in range(63):
        k0 = path[i]
        ts = [F.from_integer(t)/a0 for t in [0, 1, 255]]
        us = [u + k0 for u in ts]
        # a0 * us[0] + c1 = 0
        c1 = a0 * us[0]
        real_k = (c0 - c1)
        real_ks.append(real_k.to_integer())
        a0 *= a
        c0 += real_k
        c0 *= a
    real_ks.append((b0 * (a ** 63) + c0).to_integer())
    print(bytes(real_ks).hex())
    io.sendlineafter(b'Do you know my key?', bytes(real_ks).hex().encode())
    io.interactive()

    return True


for _ in tqdm(range(1000)):
    ret = try_solve()
    if ret:
        break


