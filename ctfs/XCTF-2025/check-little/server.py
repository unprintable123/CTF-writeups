# from secret import flag
flag = "flag{random_flag}"
from Crypto.Util.number import *  

def one(): 
    p, q = getPrime(512), getPrime(512)  
    print(p * q, p >> 233) 
    if int(input("p: ")) == p: return True
    else: return False 

def two():
    p, q = getPrime(512), getPrime(512)
    print("as:", [p*q] + [getRandomRange(1, p) * p + getRandomRange(1, p >> 200) for _ in range(3)])
    if int(input("p: ")) == p: return True
    else: return False 

def three(): 
    p = getPrime(512)
    alpha = getRandomRange(1, p) 
    for _ in range(5): x_i = getRandomRange(1, p); a_i = inverse(x_i + alpha, p) % (2**400); print(p, x_i, a_i) 
    if int(input("alpha: ")) == alpha: return True
    else: return False 
 
if all([chall() for chall in [one, two, three]]):
    print("All challenges completed successfully!")
    print(flag) 