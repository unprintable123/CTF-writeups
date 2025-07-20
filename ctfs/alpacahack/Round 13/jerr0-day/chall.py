from py_ecc import bn128 # pip install py-ecc
from ast import literal_eval

def recv_G1():
    return tuple(bn128.FQ(val) for val in literal_eval(input("Input G1: ")))

def recv_G2():
    return tuple(bn128.FQ2(val) for val in literal_eval(input("Input G2: ")))

A, B = recv_G1(), recv_G1()
C = recv_G2()

if (
    bn128.pairing(C, A) * bn128.pairing(C, B)
    ==
    bn128.pairing(C, bn128.add(A, B))
    ):
    print("Looks like it's safe!")
else:
    import os
    print(os.environ.get("FLAG", "fakeflag"))
