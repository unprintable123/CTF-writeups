from ast import literal_eval
from pwn import process, remote

def ideal_basis_gcd(I):
    """
    Computes the gcd of the coefficients of
    the ideal written as a linear combination
    of the basis of its left order.
    """
    I_basis = I.basis_matrix()
    O_basis = I.left_order().unit_ideal().basis_matrix()

    # Write I in the basis of its left order
    M = I_basis * O_basis.inverse()
    return gcd((gcd(M_row) for M_row in M))

def make_cyclic(I, full=False):
    """
    Given an ideal I, returns a cyclic ideal by dividing
    out the scalar factor g = ideal_basis_gcd(I)
    """
    g = ideal_basis_gcd(I)
    # Ideal was already cyclic
    if g == 1:
        return I, g

    print(f"DEBUG [make_cyclic]: Ideal is not cyclic, removing scalar factor: {g = }")
    J = I.scale(1/g)

    if full:
        # TODO: will remove_2_endo change g?
        # not an issue currently, as we don't
        # use this.
        return remove_2_endo(J), g
    return J, g

def ideal_generator(I, coprime_factor=1):
    """
    Given an ideal I of norm D, finds a generator
    α such that I = O(α,D) = Oα + OD

    Optional: Enure the norm of the generator is coprime 
    to the integer coprime_factor
    """
    OI = I.left_order()
    D = ZZ(I.norm())
    bound = ceil(4 * log(p))

    gcd_norm = coprime_factor * D**2

    # Stop infinite loops.
    for _ in range(1000):
        α = sum([b * randint(-bound, bound) for b in I.basis()])
        if gcd(ZZ(α.reduced_norm()), gcd_norm) == D:
            assert I == OI * α + OI * D
            return α
    raise ValueError(f"Cannot find a good α for D = {D}, I = {I}, n(I) = {D}")

def pushforward_ideal(O0, O1, I, Iτ):
    """
    Input: Ideal I left order O0
           Connecting ideal Iτ with left order O0
           and right order O1
    Output The ideal given by the pushforward [Iτ]_* I
    """
    assert I.left_order() == O0
    assert Iτ.left_order() == O0
    assert Iτ.right_order() == O1

    N = ZZ(I.norm())
    Nτ = ZZ(Iτ.norm())

    K = I.intersection(O1 * Nτ)
    α = ideal_generator(K)
    return O1 * N + O1 * (α / Nτ)

FLAG = "aliyunctf{REDACTED}"

ells = [*primes(3, 128), 163]
p = 4*prod(ells)-1
B = QuaternionAlgebra(-1, -p)
i,j,k = B.gens()
O0 = B.quaternion_order([1, i, (i+j)/2, (1+k)/2])

io = process(["sage", "task.sage"])
io.sendline(b"[0]")

io.recvuntil(b"Oa: ")
Oa_str = io.recvline().strip().decode()
io.recvuntil(b"Ob: ")
Ob_str = io.recvline().strip().decode()

Oa = B.quaternion_order(sage_eval(Oa_str, locals={"i":i,"j":j,"k":k}))
Ob = B.quaternion_order(sage_eval(Ob_str, locals={"i":i,"j":j,"k":k}))

I, _ = make_cyclic(O0*Oa)
J, _ = make_cyclic(O0*Ob)

U = pushforward_ideal(O0, J.right_order(), I, J)

serial = ""
basis = U.right_order().basis()
for b in basis:
    for c in b.coefficient_tuple():
        serial += str(c) + " "
serial = serial.strip()

io.sendline(serial)
io.interactive()
