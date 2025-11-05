"""
IRS Power Decoder with multiplicities
"""

from sage.coding.decoder import Decoder, DecodingError

from codinglib.module import * # https://bitbucket.org/jsrn/codinglib/src/master/

#import InterleavedCode

class IRSCode(InterleavedCode):
    r"""
    An Interleaving of `h` (generalized) Reed-Solomon codes with the same
    evaluation points.
    """

    def __init__(self, base_codes, order=None):
        super(IRSCode, self).__init__(base_codes, order=order)
        base_codes = self.base_codes()

        if any(not isinstance(C, codes.GeneralizedReedSolomonCode) for C in base_codes):
            raise ValueError("This class is for interleaving Reed-Solomon codes only. Use InterleavedCode for general interleaving.")
            
        alphas = base_codes[0].evaluation_points()
        if any(C.evaluation_points() != alphas for C in base_codes):
            raise ValueError("The evaluation points must be the same (and in the same order) for all the base RS codes.")

    def evaluation_points(self):
        return self.base_codes()[0].evaluation_points()

    def burst_weight_distribution(self, algorithm="base_code", prec=None):
        r"""
        Returns the weight distribution of ``self`` seen as a code over
        `GF(q^h)`, where `q` is the base field cardinality and `h` is the
        interleaving degree.
        """
        if prec:
            RR = RealField(prec)
        else:
            RR = ZZ
        n = self.base_code_length()
        # cache all needed binomial coefficients
        bins = [ [ RR( binomial(i, j) )  for j in range(i+1) ] for i in range(n+1) ]
        def weight_combined(w, A1, A2):
            "The number of codewords in (C1 | C2) of weight exactly `w`."
            return sum( A1[w1] * bins[n - w1][w - w1] *
                            sum( A2[w2] * bins[w1][w1+w2-w] for w2 in range(w-w1, w+1))
                            for w1 in range(w+1) )


        As = [ C.weight_distribution() for C in self.base_codes() ]
        A = As[0]
        for A2 in As[1:]:
            A2 = [ RR(A2[w2]/bins[n][w2]) for w2 in range(0,n+1) ] # weight per position
            A = [ weight_combined(w, A, A2) for w in range(0,n+1) ]
        return A







def irs_power_decoding_radius_real(IC, s, ell):
    r"""
    Theoretical IRS Power Decoding radius, not rounded.
    """
    if not IC.is_homogeneous():
        raise NotImplementedError("IRS Power Decoding radius for non-homogeneous IRS codes")
    k, n = IC.base_code_dimensions()[0], IC.base_code_length()
    m = IC.order()
    Ls = binomial(m + s - 1, m)
    Ll = binomial(m + ell, m)
    Ws = m * binomial(m + s - 1, m+1)
    return n * (1 - (s * Ls - Ws)/s/Ll) - m/(m+1) * ell/s * (k-1) - 1/s * (1 - 1/Ll)
    # return n * (1 + (m/(m+1) * (1 - 1/s) - 1)*binomial(m + s - 1, m)/binomial(m + ell, m)) - m/(m+1) * ell/s * (k-1) - 1/s
    # return (n*(h*binomial(h+s-1,h+1)+s*binomial(ell+h,ell)-s*binomial(s+h-1,s-1))+(k-1)*(ell*binomial(ell+h,h)-h*binomial(h+ell,h+1)))/s/binomial(ell+h,h) - ell*(k-1)/s

def irs_power_decoding_radius(IC, s, ell):
    r"""
    Theoretical IRS Power Decoding radius, rounded.
    """
    return gilt(irs_power_decoding_radius_real(IC, s, ell))

def irs_power_decoding_tau_ell_s_list(IC, ell_max=100):
    r"""
    Returns an ordered list of [tau,ell_min(tau),s_min(tau)], where ell_min(tau) is the minimal ell
    such that tau can be achieved and s_min(tau) is the corresponding minimal s.
    """
    ell_s_list = list()
    for ell in range(1,ell_max+1):
        for s in range(1,ell+1):
            tau =  irs_power_decoding_radius(IC, s, ell)
            if tau>0:
                ell_s_list.append([tau, s, ell])
    ell_s_list.sort()
    ell_s_list_minimal = list()
    last = 0
    for i in range(len(ell_s_list)):
        t = ell_s_list[i]
        if t[0]!=last:
            ell_s_list_minimal.append(t)
        last = t[0]
    return ell_s_list, ell_s_list_minimal


class IRSPowerDecoder(Decoder):

    def __init__(self, code, params):
        super(IRSPowerDecoder, self).__init__(code, code.ambient_space(), "EncodeEachCode")

        self.h = code.order()
        self.s, self.ell = params
        Px.<x> = code.base_field()[]
        self._Px = Px

        self._get_tuples()
        self._precompute()

    def decoding_radius(self):
        r"""
        The number of errors in the burst error metric that this code can correct.
        """
        return irs_power_decoding_radius(self.code(), self.s, self.ell)

    def decode_to_message(self, r):
        M = self._build_module(r)
        v = self._short_vector(M)
        Px = self._Px

        #Extract the message polynomials
        # L_all = self.L_all
        # I = identity_matrix(ZZ, self.h)
        # message_index = { i: L_all.index(list(I.row(i))) }
        Lambda = v[0]
        ms = []
        IC = self.code()
        F = IC.base_field()
        Cs = IC.base_codes()
        for i in range(self.h):
            try:
                f = Px(v[i+1]/Lambda)
            except ValueError:
                raise DecodingError("The %s'th message polynomial division did not succeed" % i)
            fl = f.list()
            pad(fl, Cs[i].dimension(), F.zero())
            ms.append(vector(fl))

        mes = _concat_vectors(ms)
        return mes


    def _precompute(self):
        """Precompute all powers of G"""
        x = self._Px.gen()
        G = prod(x-alpha for alpha in self.code().evaluation_points())
        self._Gs = make_powers(G, self.s)


    def _get_tuples(self):
        """creates two data structures:
        - self.L:       A list of length self.ell+1, containing in the i-th position the list of all h-tuple's
                        of {0,...,ell}, whose sum is i
        - self.L_all:   A list which contains all elements from the lists in self.L, in the order 0,...,ell
                        (i.e., first all tuples which sum up to 0, then, 1, ...
        """
        def flatten_once(vs):
            for v in vs:
                for e in v:
                    yield e
        ell, h = self.ell, self.h
        T = Tuples(list(range(ell + 1)), h)
        L = [[] for i in range(ell+1) ]
        for t in T:
            i = sum(t)
            if i <= ell:
                L[i].append(t)
        self.L = L
        self.L_all = list(flatten_once(self.L))


    def _base_code_lagrange(self, r, i):
        C = self.code().base_codes()[i]
        alphas = C.evaluation_points()
        betas = C.column_multipliers()
        return self._Px.lagrange_polynomial(list(zip(alphas, [ r[j]/betas[j] for j in range(C.length()) ])))

    def _build_module(self, r):
        """Build the punctured module which is a basis of the solution module"""
        IC = self.code()
        h = self.h
        s, ell, h, L_all = self.s, self.ell, self.h, self.L_all
        Px = self._Px

        Gs = self._Gs
        rs = _separate_vectors(r, h)
        Rs = [ self._base_code_lagrange(rs[i], i) for i in range(h) ] # TODO: Make powers

        a = binomial(s-1 + h, h)
        b = binomial(ell + h, h)

        def cells(i,j):
            if j==0:
                return 1 if i==0 else 0
            else:
                ti = L_all[i]
                tj = L_all[j]
                if any( i > j for (i,j) in zip(ti, tj) ):
                    return 0
                else:
                    #TODO: Simplify multiplication of Gs
                    tmp = prod( binomial(tj[mu],ti[mu])*Rs[mu]^(tj[mu]-ti[mu])*Gs[ti[mu]] for mu in range(h) if tj[mu] >= ti[mu] )
                    return tmp % Gs[s]
        S = matrix(self._Px, a, b, cells)

        M = block_matrix([ [ S ],
                           [ zero_matrix(Px, b-a, a), Gs[s] * identity_matrix(Px, b-a)] ],\
                             subdivide=False)
        return M


    def _short_vector(self, M):
        """Find the shortest weighted vector in the module"""
        k = self.code().base_code_dimensions()[0]
        ell= self.ell
        ws = [(ell - sum(t)) * (k - 1) for t in self.L_all ]
        ws[0] = ws[0] + 1
        # print ws
        # print "M initial:\n", poly_degs(M), "\n"
        module_weak_popov(M, weights=ws)
        # print "M reduced:\n", poly_degs(M), "\n"
        # print 
        sol_row = module_row_with_LP(M, 0, weights=ws)
        return M.row(sol_row)
