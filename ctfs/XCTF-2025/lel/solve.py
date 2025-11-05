from sage.all import *
from pwn import *
from ast import literal_eval
from random import randint

context.log_level = 'debug'

# io = process(['sage', 'task.sage'])
io = remote('173.32.3.15', 11421)

def recv_matrix(rows):
    matrix_lines = []
    for _ in range(rows):
        line = io.recvline().decode().strip()
        line = line.replace('  ', ' ').replace('  ', ' ').replace('  ', ' ').replace(' ', ',')
        line = line.replace('[,', '[')
        row = literal_eval(line)
        matrix_lines.append(row)
    return matrix(GF(127), matrix_lines)

def get_GH():
    io.recvuntil(b"G matrix is")
    io.recvline()
    G = recv_matrix(14)
    io.recvuntil(b"H matrix is")
    io.recvline()
    H = recv_matrix(14)
    return G, H

for _ in range(26):
    G, H = get_GH()

    A = identity_matrix(GF(127), 14)

    K = G.right_kernel().basis_matrix()

    while True:
        B_lines = []
        for i in range(26):
            vec = (H.T)[i]
            t = G.solve_right(vec)
            for _ in range(12):
                t += randint(0, 120) * K[_]
            assert G * t == vec
            B_lines.append(t.list())
        B = matrix(GF(127), B_lines).T
        if B.is_invertible():
            break
    assert A * G * B == H

    for row in A.rows():
        io.sendline(','.join(str(x) for x in row))

    for row in B.rows():
        io.sendline(','.join(str(x) for x in row))

io.interactive()
