from sage.all import *
from cysignals.alarm import alarm, AlarmInterrupt, cancel_alarm

# 2606427573325551742423779721798571211719097220082369699679901
# 344360697810972986109972173343700822544940495675251456359287217

while True:
    ps = [2]
    while prod(ps) < 2**200:
        if prod(ps) > 2**180:
            ps.append(random_prime(2**16, lbound=2**8))
        else:
            ps.append(random_prime(2**20, lbound=2**10))
        
    p = prod(ps)-1
    if not p.is_pseudoprime():
        continue
    q = (p-1)//2
    try:
        alarm(3)
        factors = q.factor(algorithm='qsieve')
        print(p.bit_length(), factors)
    except AlarmInterrupt:
        continue
    cancel_alarm()
    flag = True
    for f in factors:
        if f[0] > 2**36:
            flag = False
            break
    if flag:
        print(f'p = {p}')
        break







