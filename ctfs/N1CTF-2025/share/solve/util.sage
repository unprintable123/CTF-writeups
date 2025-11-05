import time


def random_error_pos(n, errs):
    """Return precisely errs different random numbers between 0 and n-1. errs
must be <= n"""
    errPos = []
    i = 0
    while i<n and errs>0:
        if random() < errs/(n-i):
            errPos.append(i)
            errs -= 1
        i+=1
    return errPos
    
def random_error_vec_at_pos(n, F, errPos):
    """Construct a random error vector with the given error positions (other
positions are zero)"""
    vec = [F.zero()]*n
    for i in errPos:
        while vec[i].is_zero():
            vec[i] = F.random_element()
    return vector(vec)

def random_error(n, F, errs):
    """Construct a random error vector over the field F of length n with
precisely errs non-zero entries."""
    return random_error_vec_at_pos(n, F, random_error_pos(n, errs))


def wzz_decoding_radius(n, k, interleaving_deg, powering):
    r"""
    Decoding radius of the Wachter-Zeh--Zeh IRS decoding algorithm.
    """
    s = interleaving_deg
    ell = powering
    #TODO: Should be greatest integer less than?
    return floor( ((1-n)*factorial(ell) + ((n-1)*(s+1) - ell*s*(k-1))*prod(s+h for h in range(2, ell+1)))/prod(s + h for h in range(1, ell+1)) )



def make_powers(p, max_pow):
    """Returns powers 0,1,...,max_pow of p"""
    ps = [ p.parent().one(), p ]
    for i in range(1,max_pow):
        ps.append(ps[i]*p)
    return ps

def gilt(x):
    """Greatest integer less than x"""
    if x == int(x):
        return x-1
    else:
        return int(x)

def pad(lst, n, padwith):
    """Pads the list lst in-place with padwith until it has length n. If its
    length is >= n, then it is unchanged"""
    if n > len(lst):
        lst.extend([padwith]*(n-len(lst)))

def poly_degs(T):
    """If T is a list/list of list/vector/matrix of univariate polynomials,
    return the degrees of these elements"""
    if type(T)==list or is_vector(T):
        if type(T[0])==list or is_vector(T[0]) \
           or (hasattr(T[0], "parent") and isinstance(T[0].parent(), sage.sets.cartesian_product.CartesianProduct)):
            action = 1
        else:
            action = 0
    else:
        # test whether T is a matrix, otherwise assume it is a somehow differently iterable
        if is_matrix(T):
            action = 2
        else:
            action = 0
    if action==0:
        return [ T[i].degree() for i in range(0, len(T))]
    elif action==1:
        return Matrix(ZZ, len(T), len(T[0]), lambda i,j: T[i][j].degree() if j < len(T[i]) else -2)
    elif action==2:
        return Matrix(ZZ, T.nrows(), T.ncols(), lambda i,j: T[i,j].degree())
    return None



def test_decoder(C, decoder, Ch,  N=1, silent=False, progress=False, gc=False):
    r"""Test a decoding algorithm on a linear block code with a set of N random
    codewords, subjected to random errors patterns, supposedly decodable.

    Returns a report being a list of trial results. Each trial result is a tuple
    of the form `success_code * time`.

    ``success_code`` can be one of the following: 1 means decoding success, 0
    means wrongfully decoded (not the correct codeword), -1 means that a
    `DecodingError` was thrown and caught.

    A summary is also printed out, except if silent=True.


    INPUT::

    - ``C``        - The code to test.
    - ``decoder``  - The decoder to apply.
    - ``Ch``       - The transmission channel to use.
    - ``N``        - Number of received words to decode. Default = 1.
    - ``silent``   - (default: ``False``) Do not print out any information.
    - ``progress`` - (default: ``False``) Report progress during the test
    - ``gc`` - (default: ``False``) Run the garbage collector between each
      decoding. This is important for more precise timing measurements.
    """
    report = []
    def add_to_report(success, elapsed):
        report.append((success, elapsed))
    def myprint(s):
        if not silent:
            print(s)
    progress_size = N//100 if N >= 100 else 1
    for iters in range(N):
        c = C.random_element()
        r = Ch.transmit(c)
        before = time.time()
        try:
            c_out = decoder.decode_to_code(r)
            success = 1 if c == c_out else 0
        except DecodingError as exc:
            success = -1
        elapsed = time.time() - before
        add_to_report(success, elapsed)
        if progress and iters % progress_size == 0:
            print("%s%% done" % (round(iters/N*100)+1))
    if not silent:
        times = [ elapsed for _,elapsed in report ]
        times.sort()
        successes     = sum(1 for succ,_ in report if succ == 1)
        bad_decodings = sum(1 for succ,_ in report if succ == 0)
        failures      = sum(1 for succ,_ in report if succ == -1)
        myprint("%2.3f%% decoding(s) successful (%s success, %s bad decodings and %s failures).\nDecoding took on median %7.3f secs. (from %7.3f to %7.3f secs.)"\
                % (100 * successes / N, successes, bad_decodings, failures, times[N//2], times[0], times[-1]))
    return report
