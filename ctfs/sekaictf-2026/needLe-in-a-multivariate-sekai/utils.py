from sage.all import ZZ, RealField, matrix, sqrt, round, two_squares, identity_matrix
import random
import numpy as np

def sample_unimodular(n, steps, bound=2):
    U = identity_matrix(ZZ, n)
    U_inv = identity_matrix(ZZ, n)
    
    for _ in range(steps):
        p = random.sample(range(n), n)
        U = matrix(ZZ, U[p, :])
        U_inv = matrix(ZZ, U_inv[:, p])
        for i in range(0, n - 1, 2):
            c = random.randint(-bound, bound)
            U.add_multiple_of_row(i, i+1, c)
            U_inv.add_multiple_of_column(i+1, i, -c)
                
    return U, U_inv

def sample_positive_definite_matrix(dim, bound):
    M = np.random.normal(0, bound, size=(dim, dim+1)).round().astype(int)
    M = matrix(ZZ, M.tolist())
    return M * M.transpose()

def sample_trig_sym_matrix(dim, diag_bound, bound=2):
    M = np.random.normal(0, bound, size=(dim, dim+1)).round().astype(int)
    M = np.triu(M)
    diag_samples = np.random.normal(0, diag_bound, size=dim).round().astype(int)
    M[np.diag_indices(dim)] = diag_samples
    M = matrix(ZZ, M.tolist())
    return M * M.transpose()

def sample_discrete_gaussian(n, bound):
    RF = RealField(bound.nbits() + 64)
    def next_gaussian():
        return (-2 * RF.random_element(0, 1).log()).sqrt() * (2 * RF.pi() * RF.random_element(0, 1)).cos()
    return [round(next_gaussian()*bound) for _ in range(n)]

def closest_congruent(n, p, r):
    # Find the closest number to n that is congruent to r modulo p
    rem = (n - r) % p
    if rem * 2 <= p:
        return n - rem
    else:
        return n - rem + p

def four_squares(n):
    r = 2**n.valuation(4)
    n = n // (r**2)
    RF = RealField(n.nbits() + 64)
    n_sqrt = sqrt(RF(n))
    def next_gaussian():
        return (-2 * RF.random_element(0, 1).log()).sqrt() * (2 * RF.pi() * RF.random_element(0, 1)).cos()
    def discrete_spherical(dim):
        x = [next_gaussian() for _ in range(dim)]
        norm = sqrt(sum(xi**2 for xi in x))
        return [round((xi/norm)*n_sqrt) for xi in x]
    while True:
        a, b, c, d = discrete_spherical(4)
        n0 = n - a**2 - b**2
        if n0 < 0 or n0 % 4 != 1 or ZZ(n0).is_pseudoprime() is False:
            continue
        c, d = two_squares(n0)
        c = random.choice([c, -c])
        d = random.choice([d, -d])
        assert a**2 + b**2 + c**2 + d**2 == n
        return random.sample([r*a, r*b, r*c, r*d], 4)


