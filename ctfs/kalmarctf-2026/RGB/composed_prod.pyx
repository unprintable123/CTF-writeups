# cython: boundscheck=False
# cython: wraparound=False
# cython: nonecheck=False

# ====== 全局缓存区，用于消灭海量的求逆操作 ======
cdef list INV_CACHE =[]
cdef object INV2 = None

def init_cython_cache(object p):
    global INV_CACHE, INV2
    if not INV_CACHE:
        INV_CACHE = [0] * 101
        for k in range(1, 101):
            INV_CACHE[k] = pow(k, -1, p)
        INV2 = pow(2, -1, p)

# ====== 1. 牛顿幂和与复合积核心 (全列表 C 态运行) ======
cdef list get_power_sums_c(list c, int deg, int target_N, object p):
    cdef list P =[0] * (target_N + 1)
    P[0] = deg
    cdef int k, i, limit
    cdef object s
    for k in range(1, target_N + 1):
        s = 0
        limit = k if k < deg + 1 else deg + 1 
        for i in range(1, limit):
            s += c[deg - i] * P[k - i] 
        if k <= deg:
            s += k * c[deg - k]
        P[k] = (-s) % p
    return P

cdef list composed_product_lists(list c1, list c2, object p):
    cdef int n = len(c1) - 1
    cdef int m = len(c2) - 1
    cdef int N = n * m
    
    cdef list P1 = get_power_sums_c(c1, n, N, p)
    cdef list P2 = get_power_sums_c(c2, m, N, p)
    
    cdef list Ph = [0] * (N + 1)
    cdef int i
    for i in range(N + 1):
        Ph[i] = (P1[i] * P2[i]) % p
        
    cdef list a = [0] * (N + 1)
    a[N] = 1
    
    cdef int k
    cdef object s, inv_k
    for k in range(1, N + 1):
        s = 0
        for i in range(1, k + 1):
            s += Ph[i] * a[N - k + i]
            
        inv_k = INV_CACHE[k]  # 直接调用全局逆元缓存 (O(1)级极速)
        a[N - k] = (-s * inv_k) % p
        
    return a

# 如果旧代码有调用，保留此外部接口
def composed_product_cython_hybrid(f1, f2):
    cdef object R = f1.parent()
    cdef object p = int(R.characteristic())
    init_cython_cache(p)
    cdef list c1 =[int(c) for c in f1.list()]
    cdef list c2 =[int(c) for c in f2.list()]
    return R(composed_product_lists(c1, c2, p))

# ====== 2. 纯 C 的 3x3 矩阵快速幂与特征多项式 ======
cdef list mat_mul_3x3(list A, list B, object p):
    """极其硬核的纯手工展开 3x3 矩阵乘法"""
    cdef list C = [0] * 9
    C[0] = (A[0]*B[0] + A[1]*B[3] + A[2]*B[6]) % p
    C[1] = (A[0]*B[1] + A[1]*B[4] + A[2]*B[7]) % p
    C[2] = (A[0]*B[2] + A[1]*B[5] + A[2]*B[8]) % p
    C[3] = (A[3]*B[0] + A[4]*B[3] + A[5]*B[6]) % p
    C[4] = (A[3]*B[1] + A[4]*B[4] + A[5]*B[7]) % p
    C[5] = (A[3]*B[2] + A[4]*B[5] + A[5]*B[8]) % p
    C[6] = (A[6]*B[0] + A[7]*B[3] + A[8]*B[6]) % p
    C[7] = (A[6]*B[1] + A[7]*B[4] + A[8]*B[7]) % p
    C[8] = (A[6]*B[2] + A[7]*B[5] + A[8]*B[8]) % p
    return C

cdef list mat_pow_3x3(list A, object k, object p):
    cdef list res =[1, 0, 0, 0, 1, 0, 0, 0, 1]
    cdef list base = A
    while k > 0:
        if k & 1:
            res = mat_mul_3x3(res, base, p)
        base = mat_mul_3x3(base, base, p)
        k >>= 1
    return res

cdef list find_power_poly_c(object z, object k, object p):
    # 构建 M = [[0, 0, z], [1, 0, p-1],[0, 1, 0]]
    cdef list M =[0, 0, z, 1, 0, p - 1, 0, 1, 0]
    cdef list Ak = mat_pow_3x3(M, k, p)
    
    cdef object T1 = (Ak[0] + Ak[4] + Ak[8]) % p
    
    cdef list A2 = mat_mul_3x3(Ak, Ak, p)
    cdef object T2 = (A2[0] + A2[4] + A2[8]) % p
    
    cdef object detA = pow(z, k, p)
    
    # 3x3 特征多项式推导: x^3 - Tr(A)*x^2 + 1/2*(Tr(A)^2 - Tr(A^2))*x - det(A)
    cdef object c2 = (-T1) % p
    cdef object c1 = ((T1 * T1 - T2) * INV2) % p
    cdef object c0 = (-detA) % p
    
    return[c0, c1, c2, 1] # 返回系数 [常数项, 一次项, 二次项, 三次项]


# ====== 3. 完美封装 compute_y (所有运算都在 C 层进行) ======
def compute_y_cython(object zi, list ervs_pos, list ervs_neg, object abs_v1, bint is_v1_neg, object p, object R):
    if not INV_CACHE:
        init_cython_cache(p)

    # 计算 8 个初始特征多项式
    cdef object z0 = (zi * ervs_pos[0][2]) % p
    cdef list pos_list_0 = find_power_poly_c(z0, ervs_pos[0][1], p)
    cdef object z1 = (zi * ervs_pos[1][2]) % p
    cdef list pos_list_1 = find_power_poly_c(z1, ervs_pos[1][1], p)
    cdef object z2 = (zi * ervs_pos[2][2]) % p
    cdef list pos_list_2 = find_power_poly_c(z2, ervs_pos[2][1], p)
    cdef object z3 = (zi * ervs_pos[3][2]) % p
    cdef list pos_list_3 = find_power_poly_c(z3, ervs_pos[3][1], p)
    
    cdef object nz0 = (zi * ervs_neg[0][2]) % p
    cdef list neg_list_0 = find_power_poly_c(nz0, ervs_neg[0][1], p)
    cdef object nz1 = (zi * ervs_neg[1][2]) % p
    cdef list neg_list_1 = find_power_poly_c(nz1, ervs_neg[1][1], p)
    cdef object nz2 = (zi * ervs_neg[2][2]) % p
    cdef list neg_list_2 = find_power_poly_c(nz2, ervs_neg[2][1], p)
    cdef object nz3 = (zi * ervs_neg[3][2]) % p
    cdef list neg_list_3 = find_power_poly_c(nz3, ervs_neg[3][1], p)
    
    # 全部采用内部纯列表进行复合积，消除一切外层对象创建的开销
    cdef list lhs1 = composed_product_lists(pos_list_0, pos_list_1, p)
    cdef list lhs2 = composed_product_lists(pos_list_2, pos_list_3, p)
    cdef list lhs_list = composed_product_lists(lhs1, lhs2, p)
    
    cdef list rhs1 = composed_product_lists(neg_list_0, neg_list_1, p)
    cdef list rhs2 = composed_product_lists(neg_list_2, neg_list_3, p)
    cdef list rhs_list = composed_product_lists(rhs1, rhs2, p)
    
    # ====== 高速代数换元 scaling (模拟 lhs(x = c * x) ) ======
    cdef object scale = pow(zi, abs_v1, p)
    cdef object cur_scale = 1
    cdef int i
    
    if is_v1_neg:
        for i in range(len(lhs_list)):
            lhs_list[i] = (lhs_list[i] * cur_scale) % p
            cur_scale = (cur_scale * scale) % p
    else:
        for i in range(len(rhs_list)):
            rhs_list[i] = (rhs_list[i] * cur_scale) % p
            cur_scale = (cur_scale * scale) % p
            
    # ====== 只有在最后求结式这一步，才转回 Sage 多项式并交给底层的 FLINT 运算 ======
    lhs = R(lhs_list)
    rhs = R(rhs_list)
    return lhs.resultant(rhs)