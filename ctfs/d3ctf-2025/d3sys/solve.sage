from Crypto.Util.number import bytes_to_long, getPrime, inverse, getRandomNBitInteger
import itertools
from pwn import *
from cysignals.alarm import alarm, AlarmInterrupt, cancel_alarm
import requests
from subprocess import Popen, PIPE
import re

_parse_status_re = re.compile(
        r'Using B1=(\d+), B2=(\d+), polynomial ([^,]+), sigma=(\d+)')

_found_input_re = re.compile('Found input number N')

_found_factor_re = re.compile(
    r'Found (?P<primality>.*) factor of [\s]*(?P<digits>\d+) digits: (?P<factor>\d+)')

_found_cofactor_re = re.compile(
    r'(?P<primality>.*) cofactor (?P<cofactor>\d+) has [\s]*(?P<digits>\d+) digits')

def _parse_output(n, out):
    out_lines = out.lstrip().splitlines()
    if not out_lines[0].startswith('GMP-ECM'):
        raise ValueError('invalid output')
    result = []
    for line in out_lines:
        # print('parsing line >>{0}<<'.format(line))
        m = _parse_status_re.match(line)
        if m is not None:
            group = m.groups()
            _last_params = {'B1': group[0], 'B2': group[1], 'poly': group[2], 'sigma': group[3]}
            continue
        m = _found_input_re.match(line)
        if m is not None:
            return [(n, True)]
        m = _found_factor_re.match(line)
        if m is not None:
            factor = m.group('factor')
            primality = m.group('primality')
            assert primality in ['prime', 'composite', 'probable prime']
            result += [(ZZ(factor), primality != 'composite')]
            continue  # cofactor on the next line
        m = _found_cofactor_re.match(line)
        if m is not None:
            cofactor = m.group('cofactor')
            primality = m.group('primality')
            assert primality in ['Prime', 'Composite', 'Probable prime']
            result += [(ZZ(cofactor), primality != 'Composite')]
            # assert len(result) == 2
            return result
    raise ValueError('failed to parse ECM output')

def try_factor(n):
    cmd = '/usr/bin/ecm -c 1000000000 -I 1 -one 2500'
    todo = [n]
    facs = []
    
    try:
        alarm(2)
        while todo:
            todo = sorted(todo)
            u = todo.pop(0)
            p = Popen(cmd.split(), stdout=PIPE, stdin=PIPE, stderr=PIPE, encoding='latin-1')
            out, err = p.communicate(input=str(u))
            result = _parse_output(u, out)
            for f, is_p in result:
                if is_p:
                    facs.append(f)
                else:
                    todo.append(f)
    except AlarmInterrupt:
        p.kill()
    except ValueError:
        print(u)
    finally:
        cancel_alarm()
    return facs

def small_roots(f, bounds, m=1, d=None):
	if not d:
		d = f.degree()

	if isinstance(f, Polynomial):
		x, = polygens(f.base_ring(), f.variable_name(), 1)
		f = f(x)

	R = f.base_ring()
	N = R.cardinality()
	
	f /= f.coefficients().pop(0)
	f = f.change_ring(ZZ)

	G = Sequence([], f.parent())
	for i in range(m+1):
		base = N^(m-i) * f^i
		for shifts in itertools.product(range(d), repeat=f.nvariables()):
			g = base * prod(map(power, f.variables(), shifts))
			G.append(g)

	B, monomials = G.coefficient_matrix()
	monomials = vector(monomials)

	factors = [monomial(*bounds) for monomial in monomials]
	for i, factor in enumerate(factors):
		B.rescale_col(i, factor)

	B = B.dense_matrix().LLL()

	B = B.change_ring(QQ)
	for i, factor in enumerate(factors):
		B.rescale_col(i, 1/factor)

	return B*monomials


class CRT_RSA_SYSTEM:
    nbit = 3072
    blind_bit = 153
    unknownbit = 983
    e_bit = 170

    def __init__(self):
        e = getPrime(self.e_bit)
        p,q = [getPrime(self.nbit // 2) for _ in "D^3CTF"[:2]]
        n = p * q
        self.pub = (n,e)

        dp = inverse(e,p - 1)
        dq = inverse(e,q - 1)
        self.priv = (p,q,dp,dq,e,n)
        self.blind()

    def blind(self):
        p,q,dp,dq,e,n = self.priv
        rp,rq = [getPrime(self.blind_bit) for _ in "D^3CTF"[:2]]
        dp_ = (p-1) * rp + dp
        dq_ = (q-1) * rq + dq
        self.priv = (p,q,dp_,dq_,e,n)

    def get_priv_exp(self):
        p,q,dp,dq,e,n = self.priv
        dp_ = dp >> self.unknownbit
        dq_ = dq >> self.unknownbit
        return (dp_,dq_)

    def encrypt(self,m):
        n,e = self.pub
        return pow(m,e,n)

    def decrypt(self,c):
        p,q,dp,dq,e,n = self.priv
        mp = pow(c,dp,p)
        mq = pow(c,dq,q)
        h = inverse(q, p) * (mp - mq) % p
        m = mq + h * q
        # m = crt([mp,mq],[p,q])
        assert pow(m,e,n) == c
        return m

import timeit

def powerset(iterable):
    s = list(iterable)
    return itertools.chain.from_iterable(itertools.combinations(s, r) for r in range(len(s)+1))

def test():
    rsa_sys = CRT_RSA_SYSTEM()

    dp_higher, dq_higher = rsa_sys.get_priv_exp()
    n, e = rsa_sys.pub

    p,q,dp,dq,e,n = rsa_sys.priv

    assert (dp * e) % (p - 1) == 1
    assert (dq * e) % (q - 1) == 1
    k0 = dp * e // (p - 1)
    k1 = dq * e // (q - 1)

    # print(k0)
    # print(k1)

    a0 = e * dp_higher * (2** (983))
    a1 = e * dq_higher * (2** (983))

    k_mul = (a0 * a1 // n) + 1
    assert k_mul == k0 * k1

    p_q = (k_mul * (n+1) - 1) * pow(k_mul, -1, e) % e
    assert p_q == (p + q) % e

    p_m_q2 = (p_q ** 2 - 4 * n) % e
    p_m_q = mod(p_m_q2, e).square_root()
    p_e = (p_q + p_m_q) // 2
    q_e = (p_q - p_m_q) // 2
    p_e = ZZ(p_e)
    q_e = ZZ(q_e)

    k_e0 = (-pow(p_e - 1, -1, e)) % e
    k_e1 = (-pow(q_e - 1, -1, e)) % e
    assert k_e0 in [k0 % e, k1 % e]

    facs = sorted(set(try_factor(k_mul)))
    facs = [f for f in facs if f > 5]
    if prod(facs).bit_length() < 180:
        return

    print(prod(facs).bit_length(), prod(f for f in facs if (k0 % f) == 0).bit_length(), facs, [f for f in facs if (k0 % f) == 0])

    k_u = None
    
    # enumerate subset of factors
    for sub_fac in powerset(facs):
        if len(sub_fac) == 0:
            continue
        C = prod(sub_fac)
        if C.bit_length() < 170:
            continue

        C_inv = pow(C, -1, e)
        k0_C = C_inv  * k_e0 % e
        k1_C = C_inv * k_e1 % e
        k_u = None
        if k0_C.bit_length() <= 153:
            k_u = C * k0_C
        elif k1_C.bit_length() <= 153:
            k_u = C * k1_C

        
        if k_u is not None and k_u.bit_length() <= 323:
            break
        else:
            k_u = None
    
    if k_u is None:
        return

    assert k_u.bit_length() <= 323
    assert k_u in [k0, k1]

    R.<x> = PolynomialRing(Zmod(n))

    def try_small_root(d_higher, k, real_d=None):
        # e * d_higher|??? = k * (p - 1) + 1
        # assert (e * real_d - 1) % k == 0
        # assert gcd(e * real_d - 1 + k, n) > 1
        u = (pow(e, -1, k) - d_higher * (2** (983))) % k
        # assert u == (real_d & (2** (983) - 1)) % k
        f = e * (d_higher * (2** (983)) + x * k + u) + k - 1
        # x0 = (real_d & (2** (983) - 1) - u) // k
        roots = f.monic().small_roots(X=2**670, beta=0.49, epsilon=0.05)
        if len(roots) > 0:
            x0 = roots[0]
            p = gcd(ZZ(f(x0)), n)
            assert n % p == 0 and p > 1
            q = n // p
            return p, q
        return None


    res = try_small_root(dp_higher, k_u)
    if res is None:
        res = try_small_root(dq_higher, k_u)
    print(res)
    return res
            
            
    




def test_solve(n, e, dp_higher, dq_higher):
    a0 = e * dp_higher * (2** (983))
    a1 = e * dq_higher * (2** (983))
    k_mul = (a0 * a1 // n) + 1
    p_q = (k_mul * (n+1) - 1) * pow(k_mul, -1, e) % e
    p_m_q2 = (p_q ** 2 - 4 * n) % e
    p_m_q = mod(p_m_q2, e).square_root()
    p_e = (p_q + p_m_q) // 2
    q_e = (p_q - p_m_q) // 2
    p_e = ZZ(p_e)
    q_e = ZZ(q_e)

    k_e0 = (-pow(p_e - 1, -1, e)) % e
    k_e1 = (-pow(q_e - 1, -1, e)) % e

    facs = sorted(set(try_factor(k_mul)))
    facs = [f for f in facs if f > 5]
    print(prod(facs).bit_length())

    if prod(facs).bit_length() < 180:
        return

    k_u = None
    
    # enumerate subset of factors
    for sub_fac in powerset(facs):
        if len(sub_fac) == 0:
            continue
        C = prod(sub_fac)
        if C.bit_length() < 170:
            continue

        C_inv = pow(C, -1, e)
        k0_C = C_inv  * k_e0 % e
        k1_C = C_inv * k_e1 % e
        k_u = None
        if k0_C.bit_length() <= 153:
            k_u = C * k0_C
        elif k1_C.bit_length() <= 153:
            k_u = C * k1_C

        
        if k_u is not None and k_u.bit_length() <= 323:
            break
        else:
            k_u = None
    
    if k_u is None:
        return
    
    R.<x> = PolynomialRing(Zmod(n))

    def try_small_root(d_higher, k, real_d=None):
        # e * d_higher|??? = k * (p - 1) + 1
        # assert (e * real_d - 1) % k == 0
        # assert gcd(e * real_d - 1 + k, n) > 1
        u = (pow(e, -1, k) - d_higher * (2** (983))) % k
        # assert u == (real_d & (2** (983) - 1)) % k
        f = e * (d_higher * (2** (983)) + x * k + u) + k - 1
        # x0 = (real_d & (2** (983) - 1) - u) // k
        roots = f.monic().small_roots(X=2**670, beta=0.49, epsilon=0.05)
        print(roots)
        if len(roots) > 0:
            x0 = roots[0]
            p = gcd(ZZ(f(x0)), n)
            assert n % p == 0 and p > 1
            q = n // p
            return p, q
        return None


    res = try_small_root(dp_higher, k_u)
    if res is None:
        res = try_small_root(dq_higher, k_u)
    print(res)
    return res

context.log_level = 'debug'

from hashlib import sha256
from Crypto.Util.number import long_to_bytes
from ast import literal_eval
for _ in range(256):
    io = remote('35.241.98.126', 31010)
    io.recvuntil(b'option >')
    io.send(b'G')
    io.recvuntil(b'dp,dq:')
    dp, dq = literal_eval(io.recvline().strip().decode())
    io.recvuntil(b'n,e:')
    n, e = literal_eval(io.recvline().strip().decode())[0]
    res = test_solve(n, e, dp, dq)
    if res is not None:
        p, q = res
        phi = (p - 1) * (q - 1)
        d = pow(e, -1, phi)
        print(f'Found factors: {p}, {q}')
        io.send('F')
        io.recvuntil(b'Encrypted Token:')
        token_enc = int(io.recvline().strip().decode(), 16)
        token = pow(token_enc, d, n)
        token = long_to_bytes(token)
        assert len(token) == 380
        token_hash = sha256(token).hexdigest()
        io.send(token_hash.encode())

        io.interactive()
        

    io.close()


# for _ in range(256):
#     rsa_sys = CRT_RSA_SYSTEM()
#     dp_higher, dq_higher = rsa_sys.get_priv_exp()
#     n, e = rsa_sys.pub
#     print(timeit.timeit(lambda: test_solve(n,e,dp_higher,dq_higher), number=1))
#     # print(timeit.timeit(test, number=1))

