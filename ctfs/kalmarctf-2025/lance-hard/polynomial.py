# https://github.com/jvdsn/crypto-attacks/blob/master/shared/polynomial.py
import logging

from sage.all import ZZ
from sage.all import Zmod

# from shared.crt import fast_crt


def _polynomial_hgcd(ring, a0, a1):
    assert a1.degree() < a0.degree()

    if a1.degree() <= a0.degree() / 2:
        return 1, 0, 0, 1

    m = a0.degree() // 2
    b0 = ring(a0.list()[m:])
    b1 = ring(a1.list()[m:])
    R00, R01, R10, R11 = _polynomial_hgcd(ring, b0, b1)
    d = R00 * a0 + R01 * a1
    e = R10 * a0 + R11 * a1
    if e.degree() < m:
        return R00, R01, R10, R11

    q, f = d.quo_rem(e)
    g0 = ring(e.list()[m // 2:])
    g1 = ring(f.list()[m // 2:])
    S00, S01, S10, S11 = _polynomial_hgcd(ring, g0, g1)
    return S01 * R00 + (S00 - q * S01) * R10, S01 * R01 + (S00 - q * S01) * R11, S11 * R00 + (S10 - q * S11) * R10, S11 * R01 + (S10 - q * S11) * R11


def fast_polynomial_gcd(a0, a1):
    """
    Uses a divide-and-conquer algorithm (HGCD) to compute the polynomial gcd.
    More information: Aho A. et al., "The Design and Analysis of Computer Algorithms" (Section 8.9)
    :param a0: the first polynomial
    :param a1: the second polynomial
    :return: the polynomial gcd
    """
    # TODO: implement extended variant of half GCD?
    assert a0.parent() == a1.parent()

    if a0.degree() == a1.degree():
        if a1 == 0:
            return a0
        a0, a1 = a1, a0 % a1
    elif a0.degree() < a1.degree():
        a0, a1 = a1, a0

    assert a0.degree() > a1.degree()
    if a1 == 0:
        return a0.monic()
    ring = a0.parent()

    # Optimize recursive tail call.
    while True:
        logging.debug(f"deg(a0) = {a0.degree()}, deg(a1) = {a1.degree()}")
        _, r = a0.quo_rem(a1)
        if r == 0:
            return a1.monic()

        R00, R01, R10, R11 = _polynomial_hgcd(ring, a0, a1)
        b0 = R00 * a0 + R01 * a1
        b1 = R10 * a0 + R11 * a1
        if b1 == 0:
            return b0.monic()

        _, r = b0.quo_rem(b1)
        if r == 0:
            return b1.monic()

        a0 = b1
        a1 = r

