from sage.coding.linear_code import AbstractLinearCode
from sage.coding.decoder import Decoder
from sage.coding.encoder import Encoder
# from sage.coding.channel_constructions import Channel, random_error_vector
channels._lazy_import('sage.coding.channel', ['Channel'])
print(Channel)
from sage.misc.cachefunc import cached_method


def _chop_vector(v, chop_lengths):
    r"""Chop a vector into a list of vectors of the lengths specified in ``chop_lengths``.

    ``chop_lengths`` can be a list of integers or a single integer.
    """
    bites = []
    i = 0
    if chop_lengths in ZZ:
        chop_lengths = [ chop_lengths ] * ZZ(len(v)/chop_lengths)
    for d in chop_lengths:
        bites.append(v[i:i+d])
        i += d
    return bites

def _concat_vectors(vs):
    r"""Concatenate a list of vector."""
    def flatten_once(vs):
        for v in vs:
            for e in v:
                yield e
    return vector(vs[0].base_ring(), list(flatten_once(vs)))

def _interleave_vectors(vs):
    r"""Interleave `h` vectors of the same length `n` into one vector of length `hn`."""
    def yield_interleaved(vs):
        for i in range(len(vs[0])):
            for v in vs:
                yield v[i]
    return vector(vs[0].base_ring(), list(yield_interleaved(vs)))

def _separate_vectors(v, h):
    r"""The inverse operation of ``_interleave_vectors``"""
    vs = []
    n = ZZ(len(v)/h)
    R = v.base_ring()
    for i in range(h):
        vs.append(vector(R, [ v[j*h + i] for j in range(n) ]))
    return vs


class InterleavedCode(AbstractLinearCode):

    _registered_encoders = {}
    _registered_decoders = {}

    def __init__(self, base_codes, order=None):
        r"""
        An Interleaving of `h` linear codes of the same length `n`.

        This is represented as a linear code in ``F^N``, where `N = hn`, `h`
        being the interleaving degree and `n` the length of the constituent
        codes. The codewords are laid out in an interleaved manner.

        What is usually special about interleaved codes is the error model that
        is considered, namely bursts or even "synchronized bursts": bursts which
        corrupt the same position of each base codeword (that is, it is of
        length `h` and starts at a position which is a multiple of `h`).

        INPUT::

        - ``base_codes`` - a list of linear codes of the same length `n`.
          Alternatively a single code `C`, in which case ``order`` should be
          specified.
        """
        if not order is None:
            base_codes = [ base_codes ] * order
            self._homogeneous = True
        else:
            self._homogeneous = False

        self._codes = base_codes
        n = base_codes[0].length()
        if any (C.length() != n for C in base_codes):
            raise ValueError("The base codes must all have the same length.")
            
        # alphas = base_codes[0].evaluation_points()
        # if any(C.evaluation_points() != alphas for C in base_codes):
        #     raise ValueError("The evaluation points of all the base codes have to be the same.")

        self._order = len(base_codes)
        N = n * order
        F = base_codes[0].base_ring()
        if any(C.base_ring() != F for C in base_codes):
            raise ValueError("The base field of all the base codes have to be the same.")

        self._dimension = sum(C.dimension() for C in base_codes)
        super(InterleavedCode, self).__init__(F, N, "EncodeEachCode", "Syndrome")

    def order(self):
        return self._order

    def is_homogeneous(self):
        return self._homogeneous

    def base_codes(self):
        return self._codes

    def base_code_dimensions(self):
        return [ C.dimension() for C in self.base_codes() ] 

    def base_code_length(self):
        return self._codes[0].length()

    def _repr_(self):
        return "[%s, %s] code by interleaving %s codes over GF(%s)" % (self.length(), self.dimension(), self.order(), self.base_field().cardinality())



class InterleavedEncoder(Encoder):
    r"""
    Encoder for `InterleavedCode` which uses the default encoder for the base
    codes.

    The message space is `F^K`, where `F` is the interleaved codes' base field,
    and `K` is the sum of the dimensions of the base codes. A message is then
    formed as the concatenation of messages for the base codes.

    Note that this is different from how codewords are laid out in the
    interleaved code, as these are interleavings of codewords from the base
    codes. This difference is due to the fact that the base codes might have
    different dimensions so the messages will have different lengths.
    """

    def __init__(self, code):
        super(InterleavedEncoder, self).__init__(code)

    def __eq__(self, other):
        return self.code() == other.code()

    def _repr_(self):
        return "Encoder for interleaved code by base code encoding"

    @cached_method
    def generator_matrix(self):
        IC = self.code()
        I = identity_matrix(IC.base_field(), IC.dimension())
        return matrix(IC.base_field(), IC.dimension(), IC.length(), [ self.encode(I.row(i)) for i in range(IC.dimension()) ])

    def encode(self, M):
        r"""
        Encode the message ``M`` into a codeword.
        """
        if not M in self.message_space():
            raise ValueError("Not a valid message")
        IC = self.code()
        messages = _chop_vector(M, [ C.dimension() for C in IC.base_codes() ])
        return IC.ambient_space()(_interleave_vectors([ C.encode(m) for (C, m) in zip(IC.base_codes(), messages) ]))

    def unencode(self, cw, nocheck=False):
        IC = self.code()
        return _concat_vectors([ C.unencode(c, nocheck=nocheck) for (C, c) in zip(IC.base_codes(), _separate_vectors(cw, IC.order())) ])

    def unencode_nocheck(self, cw):
        return self.unencode(cw)

InterleavedCode._registered_encoders["EncodeEachCode"] = InterleavedEncoder



class SynchronizedBurstStaticRateChannel(Channel):
    r"""
    Channel which adds a specific number of synchronized burst errors.

    In this channel, "an error" is a corruption of `h` consecutive positions of
    a transmitted vector, the first position having an index which is a multiple
    of `h`.

    INPUT::

    - ``space`` -- the input and output space, which should be `R^n` for some
      ring `R` possessing a ``random_element()`` method.

    - ``n_errs`` -- the number of errors to add to a transmitted message.

    - ``burst_length`` - the length of a burst. This number must divide `n`.
    """

    def __init__(self, space, n_errs, burst_length):
        super(SynchronizedBurstStaticRateChannel, self).__init__(space, space)
        n = space.dimension()
        if n % burst_length != 0:
            raise ValueError("The length of a burst must divide the dimension of the space.")
        self._burst_length = burst_length
        self._n_errs = n_errs

    def transmit_unsafe(self, message):
        h = self.burst_length()
        V = self.input_space()
        n = V.dimension() / h
        err_pos = sample(list(range(n)), self.number_errors())
        r = copy(message)
        R = V.base_ring()
        def random_non_zero():
            while True:
                e = R.random_element()
                if not e.is_zero():
                    return e
        for e in err_pos:
            for i in range(h):
                r[e * h + i] += random_non_zero()
        return r

    def _repr_(self):
        return "Channel for %s synchronized %s-bursts over %s" % (self.number_errors(), self.burst_length(), self.input_space())

    def burst_length(self):
        return self._burst_length

    def number_errors(self):
        return self._n_errs

    def burst_error_distance(self, v, w):
        r"""
        Return the distance between `v` and `w` in the "`h`-burst error"
        distance, where `h` is ``self.burst_length()``.

        This is the the number of blocks of length `h` which differ between `v`
        and `w`, with such blocks starting at an index divisible by `h`.
        """
        return len(self.burst_non_zero_positions(v - w))

    def burst_non_zero_positions(self, v):
        r"""
        Return the list of "burst positions" which are non-zero in `v`.

        These are indexes `i` ranging from 0 to `n-1` such that any `v_{ih + j}`
        is non-zero for `j` ranging from 0 to `h`, where `h` is
        ``self.burst_length()` and `n` is ``V.dimension()/h``, where `V` is this
        channel's space.
        """
        V = self.input_space()
        if not (v in V):
            raise ValueError("The input vector must be in %s" % V)
        h = self.burst_length()
        n = V.dimension()/h
        pos = []
        for i in range(n):
            if not v[i*h:(i+1)*h].is_zero():
                pos.append(i)
        return pos

print("Loaded interleaved_code.sage", SynchronizedBurstStaticRateChannel)