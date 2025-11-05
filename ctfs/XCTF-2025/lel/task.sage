#!/usr/bin/env sage

import sys, signal
# from flag import flag
flag = "XCTF{example_flag_for_testing}"
q, n, k = 127, 26, 14
F = GF(q)

def random_multiple(F):
    while 1:
        r = F.random_element()
        if r != 0: return r

def generate_challenge(F, k, n):
    G = random_matrix(F, k, n)
    Q = Permutations(n).random_element().to_matrix() * diagonal_matrix([random_multiple(F) for _ in range(n)])
    H = (G * Q).echelon_form()
    return G, H

print("Now start to be a challenger:")
challs = [generate_challenge(F, k, n) for _ in range(n)]
signal.alarm(10) 

for _ in range(n):
    G, H = challs[_]
    print(f"G matrix is: \n{G}")
    print(f"H matrix is: \n{H}")

    A = []
    for __ in range(k):
        ai = input().strip()
        try: A.append([int(i) for i in ai.split(',')])
        except: print("weird input.."); exit()

    B = []
    for __ in range(n):
        bi = input().strip()
        try: B.append([int(i) for i in bi.split(',')])
        except: print("weird input.."); exit()

    A, B = matrix(F, A), matrix(F, B)
    if not A.is_invertible() or not B.is_invertible():
        print("DAMN, I don't like your A,B")
        exit()

    if A * G * B != H:
        print("You lose..")
        exit()

print(flag)
