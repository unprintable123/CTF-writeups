from sage.all import *
from mpmath import mp

def babai_cvp(B, t, perform_reduction=True):
    if perform_reduction:
        B = B.LLL(delta=0.75)

    G = B.gram_schmidt()[0]
    b = t
    for i in reversed(range(B.nrows())):
        c = ((b * G[i]) / (G[i] * G[i])).round()
        b -= c * B[i]

    return b

l = 3
phi = classical_modular_polynomial(l)
flag = ZZ.from_bytes(os.environ.get('FLAG', 'jctf{ghrf65fakefd2lag}').encode())
# flag = ZZ.from_bytes(b'jctf{fakef212113lag}')
j = jp = ComplexField(1337)(1337)
print(len(flag.digits(l)), flag.digits(l))
ddd = [2, 1, 2, 2, 1, 2, 2, 0, 1, 1, 1, 2, 0, 0, 0, 1, 0, 2, 0, 2, 1, 0, 1, 0, 1, 2, 2, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 2, 1, 0, 1, 0, 0, 2, 1, 0, 2, 1, 2, 0, 1, 0, 2, 1, 1, 1, 0, 1, 0, 2, 2, 1, 0, 2, 0, 0, 1, 2, 0, 2, 2, 2, 2, 0, 0, 1, 0, 1, 2, 1, 1, 2, 0, 0, 2, 2, 1, 2, 0, 1, 2, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 2, 1, 2, 2, 0, 0, 1, 0, 1, 2, 0, 0, 2, 0, 1, 1, 1, 2, 1, 2, 1, 1, 2, 0, 1, 2, 1, 2, 2, 0, 1]
for d in ddd:
    roots = phi(X=j).univariate_polynomial().roots(multiplicities=False)
    
    roots.sort(key=jp.dist)
    del roots[0] # no turning back
    roots.sort(key=arg)
    j, jp = roots[d], j
print(j)
# exit()
target_j = j

mp.dps = 8000
pari("\p 8000")
def get_tau(j_val):
    """
    solve j(tau) = j_val
    """
    j_val = CC(j_val)
    output = pari(f"ellinit([{str(j_val)}]).omega")
    w1, w2 = output
    tau = w1 / w2
    return CC(tau)


CC = ComplexField(8000)
# target_j = CC(target_j)
target_j = CC(["-6380.29156755903034687704660000282270448709570700984709657263854520138341881550084848649839410922876936678108641559731906139407589458824525200739437427675429842545943862350406898342718600643307574207936681432539822432021043321858999100455988010088297166788530685045590301521392833041157761230553808660966639987227996254364651040683587985017755013287627806460764447918220597797227073500295101888328945378", "-40214.6672669145274363733990190234269396915010860735171342583778810557492152506583335099397606096949655915384682940536670398063862158837139959936293817852537495478495004482851179789975853315750442943613549504080182872285152393975211173312274904654221951964258004673123691758298620284682558712820558193891787303533093197420998108945366704043133890680849252774739771188873183182185315971489373696493547256"]) # i=136
t = get_tau(CC(1337))
t = (t - 4) / (t - 3)

R = PolynomialRing(RR, 'x')
xbar = R.gen()

def try_get_transform(t1, t2):
        """
        t2 = (a*t1 + b) / (c*t1 + d), a*d - b*c = 1
        """
        x0 = t1.real()
        x1 = t2.real()
        y0 = t1.imag()
        y1 = t2.imag()
        u = y0 / y1
        v1 = x0 ** 2 + y0 ** 2
        v2 = 2 * x0
        S1 = 2**3800
        S2 = 2**3000
        M = matrix(ZZ, [[S1, -S2, 0, 0], [(v1*S1).round(), 0, -S2, 0], [(v2*S1).round(), 0, 0, -S2]])
        target = vector(ZZ, [(u*S1).round(), 0, 0, 0])
        M = M.LLL()
        short_vectors = []
        v=M[0]
        v = [v[1] // S2, v[2] // S2, v[3] // S2]
        sol = babai_cvp(M, target, perform_reduction=False)
        
        dd = sol[1] // S2
        cc = sol[2] // S2
        cd = sol[3] // S2
        print(M[0][0].bit_length(), abs(sol[0]).bit_length(), sol[1].bit_length(), sol[2].bit_length(), sol[3].bit_length())
        print(cc, cd, dd)
        print(v)

        f = (dd+v[0]*xbar)*(cc+v[1]*xbar) - (cd+v[2]*xbar)**2
        rrr = f.roots(multiplicities=False)
        find = False
        print("rrr", rrr)
        for r in rrr[1:]:
            rr = r.round()
            cc2 = cc + rr * v[1]
            dd2 = dd + rr * v[0]
            cd2 = cd + rr * v[2]
            if cc2.is_square() and dd2.is_square() and gcd(cc2, dd2) == 1:
                print("Found a solution:", cc2, cd2, dd2)
                find = True
                cc, cd, dd = cc2, cd2, dd2
                break
        if not find:
            return None

        # print(cc * v1 + cd * v2 + dd - u)
        if not (cc.is_square() and dd.is_square()):
            return None
        c = sqrt(cc)
        d = sqrt(dd)
        if cd < 0:
            d = -d
        assert c * d == cd
        print(f"c = {c}, d = {d}")
        print(d**2+c**2 * v1 + cd * v2 - u)
        # c**2 * (x0**2+y0**2) + 2cd * x0 + d**2 = u
        return c, d


tau1 = t
tau2 = get_tau(target_j)
# print(target_j.dist(elliptic_j(tau2)))

print()
print(target_j)
print(elliptic_j((t+1)/3))

for i in range(10, 180):
    print("checking i =", i)
    k = 3**i
    ret = try_get_transform(tau2, tau1/k)
    if ret is None:
        continue
    c, d = ret
    print(gcd(c, d))

    _, a, b = xgcd(d, c)
    b = -b

    assert a * d - b * c == 1

    tau2_transformed = (a * tau2 + b) / (c * tau2 + d)
    u = tau2_transformed.real_part().floor()
    a -= u * c
    b -= u * d
    tau2_transformed = (a * tau2 + b) / (c * tau2 + d)
    print(tau2_transformed)
    
    u = (tau2_transformed*k).real()
    v = tau1.real()
    if abs(u.frac() - v.frac()) > abs(u.frac() - (1 - v.frac())):
        raise
        tau2_transformed = 1-tau2_transformed.conjugate()

    print((tau2_transformed*k - tau1))
    print((tau2_transformed*k - tau1).real().round(), k)
    u0 = (tau2_transformed*k - tau1).real().round()
    break

def get_j(tau):
    while True:
        tau -= tau.real_part().round()
        if tau.norm() <= 1:
            tau = -1 / tau
        else:
            break
    # print(tau)
    return elliptic_j(tau)

print(get_j((tau1+u0) / k))

# exit()

digits = []

test_j = test_jp = ComplexField(1337)(1337)

def walk(j, jp, d):
    roots = phi(X=j).univariate_polynomial().roots(multiplicities=False)
    
    roots.sort(key=jp.dist)
    del roots[0] # no turning back
    roots.sort(key=arg)
    print(roots, d)
    return roots[d], j


for i in range(400):
    if k <= 3**i:
        break

    jp = get_j((tau1+u0) / 3**(i-1))
    j0 = get_j((tau1+u0) / 3**i)
    j1 = get_j((tau1+u0) / 3**(i+1))

    roots = phi(X=ComplexField(1337)(j0)).univariate_polynomial().roots(multiplicities=False)
    roots.sort(key=jp.dist)
    del roots[0]  # no turning back
    roots.sort(key=j1.dist)
    target = roots[0]
    # print(j1.dist(target))
    assert j1.dist(target) < 1e-10, j1.dist(target)
    roots.sort(key=arg)
    d = roots.index(target)
    digits.append(d)

    assert test_j.dist(get_j((tau1+u0) / 3**(i))) < 1e-10, i
    test_j, test_jp = walk(test_j, test_jp, d)

# [2, 1, 2, 2, 1, 2, 2, 0, 1, 1, 1, 2, 0, 0, 0, 1, 0, 2, 0, 2, 1, 0, 1, 0, 1, 2, 2, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 2, 1, 0, 1, 0, 0, 2, 1, 0, 2, 1, 2, 0, 1, 0, 2, 1, 1, 1, 0, 1, 0, 2, 2, 1, 0, 2, 0, 0, 1, 2, 0, 2, 2, 2, 2, 0, 0, 1, 0, 1, 2, 1, 1, 2, 0, 0, 2, 2, 1, 2, 0, 1, 2, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 1, 0, 1, 2, 1, 2, 2, 0, 0, 1, 0, 1, 2, 0, 0, 2, 0, 1, 1, 1, 2, 1, 2, 1, 1, 2, 0, 1, 2, 1, 2, 2, 0, 1]    

print(test_j)

print("Digits:", digits)
# print(flag.digits(l))

flag = sum(d * l**i for i, d in enumerate(digits))
print(hex(flag))
print(bytes.fromhex(hex(flag)[2:]))




# print(phi(X=elliptic_j(tau2), Y=elliptic_j(tau2*3)))

# -6380.29156755903034687704660000282270448709570700984709657263854520138341881550084848649839410922876936678108641559731906139407589458824525200739437427675429842545943862350406898342718600643307574207936681432539822432021043321858999100455988010088297166788530685045590301521392833041157761230553808660966639987227996254364651040683587985017755013287627806460764447918220597797227073500295101888328945378 - 40214.6672669145274363733990190234269396915010860735171342583778810557492152506583335099397606096949655915384682940536670398063862158837139959936293817852537495478495004482851179789975853315750442943613549504080182872285152393975211173312274904654221951964258004673123691758298620284682558712820558193891787303533093197420998108945366704043133890680849252774739771188873183182185315971489373696493547256*I
