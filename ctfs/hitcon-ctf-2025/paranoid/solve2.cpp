#include <bits/stdc++.h>
#include <immintrin.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>

struct SecpK1Hasher {
    // 常量资源（实例内只读）
    EC_GROUP *group = nullptr;
    EC_POINT *pk = nullptr;
    const BIGNUM *q = nullptr;
    size_t field_bytes = 0;

    // 可复用的上下文与临时对象（实例内复用，减少开销）
    BN_CTX *ctx = nullptr;
    EC_POINT *R = nullptr;
    BIGNUM *z = nullptr, *c = nullptr, *cmod = nullptr, *negc = nullptr;
    BIGNUM *px = nullptr, *py = nullptr;
    BIGNUM *h = nullptr, *r = nullptr;
    std::vector<unsigned char> enc; // x||y 缓冲
    unsigned char digest[SHA256_DIGEST_LENGTH]{};

    SecpK1Hasher() {
        group = EC_GROUP_new_by_curve_name(NID_secp256k1);
        if (!group)
            throw std::runtime_error("EC_GROUP_new_by_curve_name failed");

        ctx = BN_CTX_new();
        if (!ctx) {
            EC_GROUP_free(group);
            throw std::runtime_error("BN_CTX_new failed");
        }

        // 求 field_bytes
        BIGNUM *p = BN_new(), *a = BN_new(), *b = BN_new();
        if (!p || !a || !b) {
            if (p)
                BN_free(p);
            if (a)
                BN_free(a);
            if (b)
                BN_free(b);
            BN_CTX_free(ctx);
            EC_GROUP_free(group);
            throw std::runtime_error("BN_new failed");
        }
        if (EC_GROUP_get_curve(group, p, a, b, ctx) != 1) {
            BN_free(p);
            BN_free(a);
            BN_free(b);
            BN_CTX_free(ctx);
            EC_GROUP_free(group);
            throw std::runtime_error("EC_GROUP_get_curve failed");
        }
        int field_bits = BN_num_bits(p);
        field_bytes = (field_bits + 7) / 8; // 32 for secp256k1
        BN_free(p);
        BN_free(a);
        BN_free(b);

        // 群阶 q（无需释放）
        q = EC_GROUP_get0_order(group);

        // 设置公钥点 pk
        const char *x_hex =
            "693bd03b5825e4810053516404914d3daeacb4b4f4c01d4634bfbdaebb34483f";
        const char *y_hex =
            "b5996db62418ceb13196219660ad14ed26180ba5b46c42e4ff9e1254f631d5f7";
        BIGNUM *x = nullptr;
        BIGNUM *y = nullptr;
        BN_hex2bn(&x, x_hex);
        BN_hex2bn(&y, y_hex);
        if (!x || !y) {
            if (x)
                BN_free(x);
            if (y)
                BN_free(y);
            BN_CTX_free(ctx);
            EC_GROUP_free(group);
            throw std::runtime_error("BN_hex2bn failed");
        }
        pk = EC_POINT_new(group);
        if (!pk) {
            BN_free(x);
            BN_free(y);
            BN_CTX_free(ctx);
            EC_GROUP_free(group);
            throw std::runtime_error("EC_POINT_new failed");
        }
        if (EC_POINT_set_affine_coordinates(group, pk, x, y, ctx) != 1) {
            BN_free(x);
            BN_free(y);
            EC_POINT_free(pk);
            BN_CTX_free(ctx);
            EC_GROUP_free(group);
            throw std::runtime_error("EC_POINT_set_affine_coordinates failed");
        }
        BN_free(x);
        BN_free(y);

        // 预分配临时对象
        R = EC_POINT_new(group);
        z = BN_new();
        c = BN_new();
        cmod = BN_new();
        negc = BN_new();
        px = BN_new();
        py = BN_new();
        h = BN_new();
        r = BN_new();
        if (!R || !z || !c || !cmod || !negc || !px || !py || !h || !r) {
            cleanup();
            throw std::runtime_error("prealloc failed");
        }

        enc.resize(2 * field_bytes);
    }

    ~SecpK1Hasher() { cleanup(); }

    // 注意：同一实例非并发安全；请让每个线程持有自己的实例
    std::array<uint64_t, 4> compute(uint64_t z_in, uint64_t c_in) {
        // 写入 z, c（小端 64 位 -> BIGNUM）
        unsigned char z_le[8], c_le[8];
        for (int i = 0; i < 8; ++i) {
            z_le[i] = static_cast<unsigned char>((z_in >> (8 * i)) & 0xFF);
            c_le[i] = static_cast<unsigned char>((c_in >> (8 * i)) & 0xFF);
        }
        if (!BN_lebin2bn(z_le, 8, z))
            throw std::runtime_error("BN_lebin2bn z failed");
        if (!BN_lebin2bn(c_le, 8, c))
            throw std::runtime_error("BN_lebin2bn c failed");

        // negc = (-c) mod q = (q - (c mod q)) mod q
        if (BN_nnmod(cmod, c, q, ctx) != 1)
            throw std::runtime_error("BN_nnmod failed");
        if (BN_is_zero(cmod)) {
            BN_zero(negc);
        } else {
            if (!BN_copy(negc, q))
                throw std::runtime_error("BN_copy failed");
            if (BN_sub(negc, negc, cmod) != 1)
                throw std::runtime_error("BN_sub failed");
        }

        // R = z*G + (-c)*pk
        if (EC_POINT_mul(group, R, z, pk, negc, ctx) != 1)
            throw std::runtime_error("EC_POINT_mul failed");

        // 取仿射坐标
        if (EC_POINT_get_affine_coordinates(group, R, px, py, ctx) != 1) {
            throw std::runtime_error("EC_POINT_get_affine_coordinates failed");
        }

        // 编码 x||y（大端，定长）
        if (BN_bn2binpad(px, enc.data(), static_cast<int>(field_bytes)) < 0 ||
            BN_bn2binpad(py, enc.data() + field_bytes,
                         static_cast<int>(field_bytes)) < 0) {
            throw std::runtime_error("BN_bn2binpad failed");
        }

        // SHA-256
        SHA256(enc.data(), enc.size(), digest);

        // 转 BN 并 mod q
        if (!BN_bin2bn(digest, SHA256_DIGEST_LENGTH, h))
            throw std::runtime_error("BN_bin2bn failed");
        if (BN_mod(r, h, q, ctx) != 1)
            throw std::runtime_error("BN_mod failed");

        // 小端 32 字节 -> 4×uint64_t（小端字序）
        unsigned char r_le[32] = {0};
        if (BN_bn2lebinpad(r, r_le, 32) < 0)
            throw std::runtime_error("BN_bn2lebinpad failed");

        std::array<uint64_t, 4> out{};
        for (int i = 0; i < 4; ++i) {
            uint64_t w = 0;
            for (int j = 0; j < 8; ++j) {
                w |= static_cast<uint64_t>(r_le[i * 8 + j]) << (8 * j);
            }
            out[i] = w;
        }
        return out;
    }

  private:
    void cleanup() {
        if (r)
            BN_free(r);
        if (h)
            BN_free(h);
        if (py)
            BN_free(py);
        if (px)
            BN_free(px);
        if (negc)
            BN_free(negc);
        if (cmod)
            BN_free(cmod);
        if (c)
            BN_free(c);
        if (z)
            BN_free(z);
        if (R)
            EC_POINT_free(R);
        if (pk)
            EC_POINT_free(pk);
        if (ctx)
            BN_CTX_free(ctx);
        if (group)
            EC_GROUP_free(group);
        group = nullptr;
        pk = nullptr;
        q = nullptr;
        ctx = nullptr;
        R = nullptr;
        z = c = cmod = negc = px = py = h = r = nullptr;
    }
};

struct SecpK1IterHasher {
    EC_GROUP *group = nullptr;
    EC_POINT *pk = nullptr;
    const BIGNUM *q = nullptr;
    size_t field_bytes = 0;

    BN_CTX *ctx = nullptr;

    // 预计算/复用的对象
    EC_POINT *inc = nullptr;    // inc = a*G
    EC_POINT *offset = nullptr; // offset = (-b)*pk
    EC_POINT *R = nullptr;      // 当前点
    BIGNUM *px = nullptr, *py = nullptr;
    BIGNUM *h = nullptr, *r = nullptr;

    std::vector<unsigned char> enc; // x||y 缓冲 2*field_bytes
    unsigned char digest[SHA256_DIGEST_LENGTH]{};

    bool initialized = false;

    SecpK1IterHasher(uint64_t a, uint64_t b) {
        group = EC_GROUP_new_by_curve_name(NID_secp256k1);
        ctx = BN_CTX_new();

        // field_bytes
        BIGNUM *p = BN_new(), *aa = BN_new(), *bb = BN_new();
        EC_GROUP_get_curve(group, p, aa, bb, ctx);
        int field_bits = BN_num_bits(p);
        field_bytes = (field_bits + 7) / 8;
        BN_free(p);
        BN_free(aa);
        BN_free(bb);

        q = EC_GROUP_get0_order(group);

        // 设置公钥点 pk
        const char *x_hex =
            "693bd03b5825e4810053516404914d3daeacb4b4f4c01d4634bfbdaebb34483f";
        const char *y_hex =
            "b5996db62418ceb13196219660ad14ed26180ba5b46c42e4ff9e1254f631d5f7";
        BIGNUM *x = nullptr;
        BIGNUM *y = nullptr;
        BN_hex2bn(&x, x_hex);
        BN_hex2bn(&y, y_hex);
        pk = EC_POINT_new(group);
        EC_POINT_set_affine_coordinates(group, pk, x, y, ctx);
        BN_free(x);
        BN_free(y);

        // 预分配对象
        inc = EC_POINT_new(group);
        offset = EC_POINT_new(group);
        R = EC_POINT_new(group);
        px = BN_new();
        py = BN_new();
        h = BN_new();
        r = BN_new();

        enc.resize(2 * field_bytes);

        // 计算 inc = a*G
        unsigned char a_le[8];
        for (int i = 0; i < 8; ++i)
            a_le[i] = (unsigned char)((a >> (8 * i)) & 0xFF);
        BIGNUM *a_bn = BN_lebin2bn(a_le, 8, nullptr);
        EC_POINT_mul(group, inc, a_bn, nullptr, nullptr, ctx);
        BN_free(a_bn);

        // 计算 offset = (-b)*pk，通过先算 b*pk 再取负
        unsigned char b_le[8];
        for (int i = 0; i < 8; ++i)
            b_le[i] = (unsigned char)((b >> (8 * i)) & 0xFF);
        BIGNUM *b_bn = BN_lebin2bn(b_le, 8, nullptr);
        EC_POINT_mul(group, offset, nullptr, pk, b_bn, ctx);
        EC_POINT_invert(group, offset, ctx); // offset = -b*pk
        BN_free(b_bn);

        initialized = false;
    }

    ~SecpK1IterHasher() {
        if (r)
            BN_free(r);
        if (h)
            BN_free(h);
        if (py)
            BN_free(py);
        if (px)
            BN_free(px);
        if (R)
            EC_POINT_free(R);
        if (offset)
            EC_POINT_free(offset);
        if (inc)
            EC_POINT_free(inc);
        if (pk)
            EC_POINT_free(pk);
        if (ctx)
            BN_CTX_free(ctx);
        if (group)
            EC_GROUP_free(group);
    }

    // 每次调用：第一次返回 z=a,c=b；之后每次在上次结果上加 inc（z += a）
    std::array<uint64_t, 4> compute() {
        if (!initialized) {
            EC_POINT_add(group, R, offset, inc, ctx); // R = (-b)*pk + a*G
            initialized = true;
        } else {
            EC_POINT_add(group, R, R, inc, ctx); // R += a*G
        }

        // 取仿射坐标
        EC_POINT_get_affine_coordinates(group, R, px, py, ctx);

        // 编码 x||y（大端定长）
        BN_bn2binpad(px, enc.data(), (int)field_bytes);
        BN_bn2binpad(py, enc.data() + field_bytes, (int)field_bytes);

        // SHA-256
        SHA256(enc.data(), enc.size(), digest);

        // 按大端转整数并对 q 取模
        BN_bin2bn(digest, SHA256_DIGEST_LENGTH, h);
        BN_mod(r, h, q, ctx);

        // 输出为 32 字节小端，再拆成 4×uint64_t（小端）
        unsigned char r_le[32] = {0};
        BN_bn2lebinpad(r, r_le, 32);

        std::array<uint64_t, 4> out{};
        for (int i = 0; i < 4; ++i) {
            uint64_t w = 0;
            for (int j = 0; j < 8; ++j) {
                w |= (uint64_t)r_le[i * 8 + j] << (8 * j);
            }
            out[i] = w;
        }
        return out;
    }
};

int highest_bit(uint64_t x, bool k) {
    if (!k) {
        return 63 - __builtin_clzll(x);
    }
    return 63 - __builtin_clzll(~x);
}

struct int256 {
    std::array<uint64_t, 4> val;
    int256() { val[0] = val[1] = val[2] = val[3] = 0; }
    int256(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3) {
        val[0] = a0, val[1] = a1, val[2] = a2, val[3] = a3;
    }
    int256(const std::array<uint64_t, 4> &mod_q_val);

    static inline unsigned char addcarry_u64(unsigned char c, uint64_t a,
                                             uint64_t b, uint64_t &out) {
        return _addcarry_u64(c, a, b, (unsigned long long *)&out);
    }

    static inline unsigned char subborrow_u64(unsigned char b, uint64_t a,
                                              uint64_t c, uint64_t &out) {
        return _subborrow_u64(b, a, c, (unsigned long long *)&out);
    }

    int256 &operator+=(const int256 &rhs) {
        unsigned char c = 0;
        c = addcarry_u64(c, val[0], rhs.val[0], val[0]);
        c = addcarry_u64(c, val[1], rhs.val[1], val[1]);
        c = addcarry_u64(c, val[2], rhs.val[2], val[2]);
        c = addcarry_u64(c, val[3], rhs.val[3], val[3]);
        return *this; // 溢出回绕
    }

    int256 &operator-=(const int256 &rhs) {
        unsigned char b = 0;
        b = subborrow_u64(b, val[0], rhs.val[0], val[0]);
        b = subborrow_u64(b, val[1], rhs.val[1], val[1]);
        b = subborrow_u64(b, val[2], rhs.val[2], val[2]);
        b = subborrow_u64(b, val[3], rhs.val[3], val[3]);
        return *this; // 溢出回绕
    }

    friend int256 operator+(int256 lhs, const int256 &rhs) {
        lhs += rhs;
        return lhs;
    }
    friend int256 operator-(int256 lhs, const int256 &rhs) {
        lhs -= rhs;
        return lhs;
    }

    bool operator<(const int256 &rhs) const {
        if (val[3] != rhs.val[3])
            return val[3] < rhs.val[3];
        if (val[2] != rhs.val[2])
            return val[2] < rhs.val[2];
        if (val[1] != rhs.val[1])
            return val[1] < rhs.val[1];
        return val[0] < rhs.val[0];
    }
    bool operator>(const int256 &rhs) const { return rhs < *this; }
    bool operator<=(const int256 &rhs) const { return !(*this > rhs); }
    bool operator>=(const int256 &rhs) const { return !(*this < rhs); }
    bool operator==(const int256 &rhs) const {
        return val[0] == rhs.val[0] && val[1] == rhs.val[1] &&
               val[2] == rhs.val[2] && val[3] == rhs.val[3];
    }

    bool is_neg() const { return val[3] >> 63; }

    // return the log of highest non-k bit
    int highest_bit(bool k) const {
        uint64_t full_k = k ? (~0ul) : 0;
        if (val[3] == full_k) {
            if (val[2] == full_k) {
                if (val[1] == full_k) {
                    if (val[0] == full_k) {
                        return -1;
                    }
                    return ::highest_bit(val[0], k);
                }
                return ::highest_bit(val[1], k) + 64;
            }
            return ::highest_bit(val[2], k) + 128;
        }
        return ::highest_bit(val[3], k) + 192;
    }
};

int256 q(0xbfd25e8cd0364141ul, 0xbaaedce6af48a03bul, 0xfffffffffffffffeul,
         0xfffffffffffffffful);
int256 inv0(0xfffffffffffffffful, 0xfffffffffffffffful, 0xfffffffffffffffful,
            0xfffffffffffffffful);

int256::int256(const std::array<uint64_t, 4> &mod_q_val) {
    if (mod_q_val[3] >> 63) {
        int256 t(mod_q_val[0], mod_q_val[1], mod_q_val[2], mod_q_val[3]);
        *this = t - q;
        // val[0] = val[3], val[1] = val[2] = val[3] = ~0ul;
    } else {
        val[0] = mod_q_val[0];
        val[1] = mod_q_val[1];
        val[2] = mod_q_val[2];
        val[3] = mod_q_val[3];
        // val[0] = val[3], val[1] = val[2] = val[3] = 0;
    }
}

// n - tree depth
// m - values on each tree node
const int n = 13, m = 20, m_leaf = 12, half_n = n / 2;
const int bucket_size = m + 1;

struct node {
    int256 vals[1 << m], leaf_raw_vals[1 << m];
    int mid, size; // [0,mid) - <0, [mid,size) - >0
    int256 max_abs() const {
        if (!vals[0].is_neg()) {
            return vals[(1 << m) - 1];
        }
        if (vals[(1 << m) - 1].is_neg()) {
            return int256() - vals[0];
        }
        return std::max(int256() - vals[0], vals[(1 << m) - 1]);
    }
};

struct compute_ctx {
    // buffers
    int256 a[1 << m], b[1 << m];
    int c[(1 << bucket_size) + 1];
    std::vector<int256> d;
    compute_ctx() { d.reserve(1 << (m + 3)); }
    int sort_to(int256 *vals, int256 *dst, int size);
    void sort_samesign_to(int256 *s, int slen, int256 *d, int bucket_bit);
    void merge(int256 ls[1 << m], int256 rs[1 << m], int merge_bit, int size);
    std::pair<int, int> merge_find(int256 ls[1 << m], int256 rs[1 << m],
                                   int256 target, int merge_bit, int size);
};

node *nodes[1 << (n + 1)];
int status[1 << (n + 1)];

int compute_ctx::sort_to(int256 *vals, int256 *dst, int size) {
    int ac = 0, bc = 0;
    int256 a_max, b_min = inv0;
    for (int i = 0; i < size; i++) {
        const auto &t = vals[i];
        if (!t.is_neg()) {
            a[ac++] = t;
            if (t > a_max)
                a_max = t;
        } else {
            b[bc++] = t;
            if (t < b_min)
                b_min = t;
        }
    }
    // sort negative part
    int low = std::max(0, b_min.highest_bit(1) - bucket_size + 1);
    sort_samesign_to(b, bc, dst, low);
    // sort positive part
    low = std::max(0, a_max.highest_bit(0) - bucket_size + 1);
    sort_samesign_to(a, ac, dst + bc, low);
    return bc;
}

inline void small_sort(int256 *s, int n) {
    if (n <= 1)
        return;
    if (n == 2) {
        if (s[0] > s[1])
            std::swap(s[0], s[1]);
        return;
    }
    if (n == 3) {
        if (s[0] > s[1])
            std::swap(s[0], s[1]);
        if (s[1] > s[2])
            std::swap(s[1], s[2]);
        if (s[0] > s[1])
            std::swap(s[0], s[1]);
        return;
    }
    std::sort(s, s + n);
}

void compute_ctx::sort_samesign_to(int256 *s, int slen, int256 *d,
                                   int bucket_bit) {
    // we use m+1 bits for bucket sort
    int bucket_bit_high = bucket_bit + bucket_size - 1;
    for (int i = 0; i <= (1 << bucket_size); i++) {
        c[i] = 0;
    }
    if ((bucket_bit >> 6) == (bucket_bit_high >> 6)) {
        int bucket_u64_id = bucket_bit >> 6;
        int bucket_bit_in_u64 = bucket_bit & 63;
        const int mask = (1 << bucket_size) - 1;
        for (int i = 0; i < slen; i++) {
            int bucket = s[i].val[bucket_u64_id] >> bucket_bit_in_u64 & mask;
            c[bucket]++;
        }
        for (int i = 1; i <= (1 << bucket_size); i++) {
            c[i] += c[i - 1];
        }
        for (int i = 0; i < slen; i++) {
            int bucket = s[i].val[bucket_u64_id] >> bucket_bit_in_u64 & mask;
            d[--c[bucket]] = s[i];
        }
    } else {
        int bucket_u64_id = bucket_bit >> 6;
        int bucket_bit_in_u64 = bucket_bit & 63;
        const int shift2 = 64 - bucket_bit_in_u64;
        const int mask = (1 << (bucket_size - shift2)) - 1;
        for (int i = 0; i < slen; i++) {
            int bucket = s[i].val[bucket_u64_id] >> bucket_bit_in_u64 |
                         (s[i].val[bucket_u64_id + 1] & mask) << shift2;
            c[bucket]++;
        }
        for (int i = 1; i <= (1 << bucket_size); i++) {
            c[i] += c[i - 1];
        }
        for (int i = 0; i < slen; i++) {
            int bucket = s[i].val[bucket_u64_id] >> bucket_bit_in_u64 |
                         (s[i].val[bucket_u64_id + 1] & mask) << shift2;
            d[--c[bucket]] = s[i];
        }
    }
    for (int i = 0; i < (1 << bucket_size); i++) {
        small_sort(d + c[i], c[i + 1] - c[i]);
    }
}

void compute_ctx::merge(int256 ls[1 << m], int256 rs[1 << m], int merge_bit,
                        int size) {
    // find all ls[i]+rs[j] that all bits>=merge bit is 0 or 1
    int i = size - 1, j = 0;
    int256 range_l, range_r;
    for (int k = merge_bit; k < 256; k++)
        range_l.val[k >> 6] |= 1ul << (k & 63);
    for (int k = 0; k < 4; k++)
        range_r.val[k] = ~range_l.val[k];
    d.resize(0);
    for (; i >= 0; i--) {
        for (int256 t;
             j < size && ((t = ls[i] + rs[j]), t.is_neg() && t < range_l); j++)
            ;
        // all ls[i]+rs[>=j] >= range_l
        for (int k = j; k < size; k++) {
            int256 t = ls[i] + rs[k];
            if (!t.is_neg() && t > range_r)
                break;
            d.push_back(t);
        }
    }
}

std::pair<int, int> compute_ctx::merge_find(int256 ls[1 << m],
                                            int256 rs[1 << m], int256 target,
                                            int merge_bit, int size) {
    // find all ls[i]+rs[j] that all bits>=merge bit is 0 or 1
    int i = size - 1, j = 0;
    int256 range_l, range_r;
    for (int k = merge_bit; k < 256; k++)
        range_l.val[k >> 6] |= 1ul << (k & 63);
    for (int k = 0; k < 4; k++)
        range_r.val[k] = ~range_l.val[k];
    for (; i >= 0; i--) {
        for (int256 t;
             j < size && ((t = ls[i] + rs[j]), t.is_neg() && t < range_l); j++)
            ;
        // all ls[i]+rs[>=j] >= range_l
        for (int k = j; k < size; k++) {
            int256 t = ls[i] + rs[k];
            if (!t.is_neg() && t > range_r)
                break;
            if (t == target) {
                return std::make_pair(i, k);
            }
        }
    }
    return std::make_pair(-1, -1);
}

node *get_node(size_t node_index) {
#pragma omp critical
    {
        if (!nodes[node_index]) {
            nodes[node_index] = new node();
        }
        return nodes[node_index];
    }
}

void free_node(size_t node_index) {
#pragma omp critical
    {
        if (nodes[node_index]) {
            delete nodes[node_index];
            nodes[node_index] = 0;
        }
    }
}

struct abs_cmp {
    bool operator()(const int256 &lhs, const int256 &rhs) {
        bool lhs_neg = lhs.is_neg();
        bool rhs_neg = rhs.is_neg();
        if (!lhs_neg && !rhs_neg) {
            return lhs < rhs;
        }
        if (lhs_neg && rhs_neg) {
            return lhs > rhs;
        }
        int256 t = lhs + rhs;
        bool t_neg = t.is_neg();
        return lhs_neg ^ t_neg;
    }
};

void compute_node(compute_ctx *ctx, size_t node_index, bool free) {
    node *cur_node = get_node(node_index);
    if (node_index >> n) { // leaf
        int tree_index = node_index - (1 << n);
        SecpK1IterHasher h(1, tree_index);
        for (int i = 0; i < (1 << m_leaf); i++) {
            cur_node->leaf_raw_vals[i] = int256(h.compute());
        }
        cur_node->mid = ctx->sort_to(cur_node->leaf_raw_vals, cur_node->vals,
                                     (1 << m_leaf));
        cur_node->size = 1 << m_leaf;
    } else {
        node *lc = get_node(node_index << 1);
        node *rc = get_node(node_index << 1 | 1);
        int256 max_abs = std::max(lc->max_abs(), rc->max_abs());
        int max_bit = max_abs.highest_bit(0);
        for (int trial_bit = std::min(
                 255, std::max(1, max_bit -
                                      ((node_index >> (n - 1)) ? m_leaf * 2 - m
                                                               : m) +
                                      2));
             ; trial_bit++) {
            ctx->merge(lc->vals, rc->vals, trial_bit, lc->size);
            if (ctx->d.size() >= (1 << m))
                break;
        }
        std::nth_element(ctx->d.begin(), ctx->d.begin() + (1 << m),
                         ctx->d.end(), abs_cmp());
        cur_node->mid = ctx->sort_to(ctx->d.data(), cur_node->vals, 1 << m);
        cur_node->size = 1 << m;
        if (free) {
            free_node(node_index << 1);
            free_node(node_index << 1 | 1);
        }
    }
#pragma omp critical
    {
        printf("compute %ld done\n", node_index);
        status[node_index] = 2;
    }
}

int find_job_1() {
    int result = 0;
#pragma omp critical
    {
        for (int i = 1; i < (1 << (n + 1)); i++) {
            if (status[i] == 0 &&
                (i >= (1 << n) ||
                 (status[i << 1] == 2 && status[i << 1 | 1] == 2))) {
                result = i;
                status[i] = 1;
                break;
            }
        }
    }
    return result;
}

void do_jobs_1() {
    compute_ctx *ctx = new compute_ctx();
    while (1) {
        int node_index = find_job_1();
        if (!node_index)
            break;
        compute_node(ctx, node_index, node_index >= (1 << half_n));
    }
    delete ctx;
}

int256 sol_sum[1 << (n + 1)];
int sol_status[1 << (n + 1)], solution[1 << n];

void decomposite_node(compute_ctx *ctx, size_t node_index) {
    node *cur_node = get_node(node_index);
    if (node_index >> n) { // leaf
        for (int i = 1; i <= (1 << m_leaf); i++) {
            if (cur_node->leaf_raw_vals[i - 1] == sol_sum[node_index]) {
                solution[node_index - (1 << n)] = i;
                break;
            }
        }
    } else {
        node *lc = get_node(node_index << 1);
        node *rc = get_node(node_index << 1 | 1);
        int256 max_abs = std::max(lc->max_abs(), rc->max_abs());
        int max_bit = max_abs.highest_bit(0);
        for (int trial_bit = std::min(
                 255, std::max(1, max_bit -
                                      ((node_index >> (n - 1)) ? m_leaf * 2 - m
                                                               : m) +
                                      2));
             ; trial_bit++) {
            auto t = ctx->merge_find(lc->vals, rc->vals, sol_sum[node_index],
                                     trial_bit, lc->size);
            if (t.first != -1) {
                sol_sum[node_index << 1] = lc->vals[t.first];
                sol_sum[node_index << 1 | 1] = rc->vals[t.second];
#pragma omp critical
                {
                    sol_status[node_index << 1] = 1;
                    sol_status[node_index << 1 | 1] = 1;
                }
                break;
            }
        }
    }
    free_node(node_index);
#pragma omp critical
    {
        printf("decomposite %ld done\n", node_index);
        status[node_index] = 2;
    }
}

int find_job_2() {
    int result = 0;
#pragma omp critical
    {
        // first, try to find an decomposite job
        for (int i = 1; i < (1 << (n + 1)); i++) {
            if (sol_status[i] == 1 &&
                (i >= (1 << n) ||
                 (status[i << 1] == 2 && status[i << 1 | 1] == 2))) {
                result = -i;
                sol_status[i] = 2;
                break;
            }
        }
        // then, try to find an composite job
        if (!result) {
            for (int i = 1; i < (1 << (n + 1)); i++) {
                if (status[i] == 0 &&
                    (i >= (1 << n) ||
                     (status[i << 1] == 2 && status[i << 1 | 1] == 2))) {
                    result = i;
                    status[i] = 1;
                    break;
                }
            }
        }
    }
    return result;
}

void do_jobs_2() {
    compute_ctx *ctx = new compute_ctx();
    while (1) {
        int node_index = find_job_2();
        if (!node_index)
            break;
        if (node_index > 0) {
            // don't free, it will be done in decomposite
            compute_node(ctx, node_index, false);
        } else {
            decomposite_node(ctx, -node_index);
        }
    }
    delete ctx;
}

int main() {
#pragma omp parallel num_threads(29)
    {
        do_jobs_1();
    }
    node *root = get_node(1);
    std::nth_element(root->vals, root->vals + 1, root->vals + (1 << m),
                     abs_cmp());
    sol_sum[1] = root->vals[0];
    printf("%016lx%016lx%016lx%016lx\n", sol_sum[1].val[3], sol_sum[1].val[2],
           sol_sum[1].val[1], sol_sum[1].val[0]);
    sol_status[1] = 1;
    for (int i = 1; i < (1 << (n + 1)); i++)
        if (!nodes[i])
            status[i] = 0;
#pragma omp parallel num_threads(29)
    {
        do_jobs_2();
    }
    SecpK1Hasher h;
    int256 sum;
    for (int i = 0; i < (1 << n); i++) {
        auto a = h.compute(solution[i], i);
        // printf("%d %d\n%016lx%016lx%016lx%016lx\n", i, solution[i], a[3],
        // a[2], a[1], a[0]);
        int256 b(a);
        sum += b;
    }
    printf("%016lx%016lx%016lx%016lx\n", sum.val[3], sum.val[2], sum.val[1],
           sum.val[0]);
    FILE *f = fopen("solution.txt", "w");
    for (int i = 0; i < (1 << n); i++) {
        printf("%d%c", solution[i], i + 1 == (1 << n) ? '\n' : ' ');
        fprintf(f, "%d%c", solution[i], i + 1 == (1 << n) ? '\n' : ' ');
    }
    fclose(f);
}