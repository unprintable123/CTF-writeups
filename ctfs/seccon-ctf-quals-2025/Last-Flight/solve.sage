from Crypto.Util.number import *
from random import randint
import os
from pwn import *

p = 4718527636420634963510517639104032245020751875124852984607896548322460032828353
j = 4667843869135885176787716797518107956781705418815411062878894329223922615150642

flag = os.getenv("FLAG", "SECCON{test_flag}")


def interstellar_flight(j, flight_plans=None):
    planet = EllipticCurve(GF(p), j=j)
    visited_planets = []
    if flight_plans == None:
        flight_plans = [randint(0, 2) for _ in range(160)]

    for flight_plan in flight_plans:
        print(planet.j_invariant(), [iso.codomain().j_invariant() for iso in planet.isogenies_prime_degree(2)])
        flight = planet.isogenies_prime_degree(2)[flight_plan]
        if len(visited_planets) > 1:
            if flight.codomain().j_invariant() == visited_planets[-2]:
                continue
        planet = flight.codomain()
        visited_planets.append(planet.j_invariant())
    return visited_planets[-1]


print("Currently in interstellar flight...")

# j_target = GF(p)(-640320)**3

root_j = GF(p)(-640320)**3

def generic_modular_polynomial_roots(j1):
    """
    Compute the roots to the Modular polynomial
    Φ2, setting x to be the input j-invariant.

    When only one j-invariant is known, we
    find up to three new j-invariant values.

    This is fairly slow, but is only done
    once per graph.
    """
    R = PolynomialRing(j1.parent(), "y")
    y = R.gens()[0]
    Φ2 = (
        j1**3
        - j1**2 * y**2
        + 1488 * j1**2 * y
        - 162000 * j1**2
        + 1488 * j1 * y**2
        + 40773375 * j1 * y
        + 8748000000 * j1
        + y**3
        - 162000 * y**2
        + 8748000000 * y
        - 157464000000000
    )

    return Φ2.roots(multiplicities=False)

def quadratic_roots(b, c):
    """
    Computes roots to the quadratic polynomial

        f = x^2 + b * x + c

    Using the quadratic formula

    Just like in school!
    """
    d2 = b**2 - 4 * c
    try:
        d = d2.square_root()
        return ((-b + d) / 2, -(b + d) / 2)
    except:
        return []

def quadratic_modular_polynomial_roots(jc, jp):
    """
    When we have the current node's value as
    well as the parent node value then we can
    find the remaining roots by solving a
    quadratic polynomial following
    
    https://ia.cr/2021/1488
    """
    jc_sqr = jc**2
    α = -jc_sqr + 1488 * jc + jp - 162000
    β = (
        jp**2
        - jc_sqr * jp
        + 1488 * (jc_sqr + jc * jp)
        + 40773375 * jc
        - 162000 * jp
        + 8748000000
    )
    # Find roots to x^2 + αx + β
    return quadratic_roots(α, β)

def test_depth(j_start):
    next_js = [iso.codomain().j_invariant() for iso in EllipticCurve(GF(p), j=j_start).isogenies_prime_degree(2)]
    path = []
    for next_j in next_js:
        history = [j_start, next_j]
        j = next_j
        while True:
            find = False
            # for iso in EllipticCurve(GF(p), j=j).isogenies_prime_degree(2):
            #     j1 = iso.codomain().j_invariant()
            for j1 in quadratic_modular_polynomial_roots(j, history[-2]):
                if j1 not in history:
                    find = True
                    history.append(j1)
                    j=j1
                    break
            if not find:
                path.append(history)
                break
    data = [(len(p0), p0[1]) for p0 in path]
    data = sorted(data, key=lambda x: x[0])
    depth = data[0][0]
    parent = data[-1][1]
    return depth, parent
    
def climb(j_start):
    path = [j_start]
    while True:
        d, parent = test_depth(j_start)
        if d == 129:
            break
        path.append(parent)
        j_start = parent
        print("Climbing...", d)
    return path + [root_j]

def find_path(ja, jb):
    path_a = climb(ja)
    print()
    path_b = climb(jb)
    while path_a[-2] == path_b[-2]:
        path_a.pop()
        path_b.pop()
    print(path_a, path_b)
    assert path_a[-1] == path_b[-1]
    new_path = path_a[:-1] + path_b[::-1]
    print(new_path)
    assert new_path[0] == ja and new_path[-1] == jb
    cur_j = new_path.pop(0)
    planet = EllipticCurve(GF(p), j=cur_j)
    plan = []
    while cur_j != jb:
        fs = planet.isogenies_prime_degree(2)
        find = False
        for idx, iso in enumerate(fs):
            planet = iso.codomain()
            if planet.j_invariant() == new_path[0]:
                plan.append(idx)
                cur_j = new_path.pop(0)
                find = True
                break
        assert find
        print("Descending...", len(new_path))
    return plan

# ja = interstellar_flight(root_j,[1,1])
# jb = interstellar_flight(root_j,[0,0])
# path = find_path(ja, jb)
# print(path)
# print(interstellar_flight(ja, path))
# print(jb)

# io = process(['sage', 'chall.sage'])
# nc last-flight.seccon.games 5000
io = remote('last-flight.seccon.games', 5000)
io.recvuntil(b"vulcan's planet is here :")
vulcan = int(io.recvline().strip().decode())
io.recvuntil(b"bell's planet is here :")
bell = int(io.recvline().strip().decode())
plan = find_path(vulcan, bell)
print(plan)
io.sendline(", ".join(str(x) for x in plan))
io.interactive()

