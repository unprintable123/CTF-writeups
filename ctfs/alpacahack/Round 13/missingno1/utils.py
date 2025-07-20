def element_to_int(elem):
    F = elem.parent()
    p = F.characteristic()
    coeffs = elem.polynomial().coefficients(sparse=False)
    return sum(int(c) * (p ** i) for i, c in enumerate(coeffs))

def int_to_element(value, F):
    p = F.characteristic()
    coeffs = []
    for _ in range(F.degree()):
        coeffs.append(value % p)
        value //= p
    return F(coeffs)
