from Crypto.Util.number import *
from hashlib import md5
# from secret import flag
import signal

flag = "suctf{test_flag}"

PR.<x> = PolynomialRing(Zmod(0xfffffffffffffffffffffffffffffffe))
SUPOLY = PR.random_element(10)
gift = []
for i in range(bytes_to_long(b"SU")):
    f = PR.random_element(10)
    gift.append([int((f*SUPOLY)(j)) & 0xff for j in range(10)])
print("🎁 :", gift)

signal.alarm(10)
if(md5(str(SUPOLY.list()).encode()).hexdigest() == input("Show me :)")):
    print("🚩 :", flag)
else:
    print("🏳️ :", "flag")
    print(SUPOLY)