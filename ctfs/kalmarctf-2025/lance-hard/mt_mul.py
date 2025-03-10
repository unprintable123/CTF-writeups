from sage.all import *
from mul import fast_MV_Element, fast_MV_Ring
import sys
# from sage.misc.persist import SagePickler, SageUnpickler
import pickle
import base64

p = 1208925819614629174706189
R0 = PolynomialRing(GF(p), 'r')
r = R0.gen(0)

index = int(sys.argv[1])
num_threads = int(sys.argv[2])
tmp_file = sys.argv[3]
log_file = sys.argv[4]

f1, f2 = load(tmp_file)

f = f1.mul_part(f2, index, num_threads, log_file)

def to_list(poly):
    if hasattr(poly, "list"):
        return list(map(int, poly.list()))
    else:
        return [int(poly)]

coeffs = [to_list(poly) for poly in f.coeffs]
print(base64.b64encode(pickle.dumps(coeffs)).decode())



