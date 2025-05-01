#include <NTL/ZZ.h>
#include <NTL/mat_ZZ.h>
#include <NTL/LLL.h>
#include <gmpxx.h>
#include <iostream>
#include <cassert>
#include <vector>
#include <chrono>
#include <thread>
#include <mutex>

using namespace NTL;
using namespace std;

#define nbits 34

void ntl2gmp(mpz_t out, NTL::ZZ const &num)
{
    thread_local std::vector<unsigned char> bs;

    if (NTL::IsZero(num))
    {
        mpz_set_ui(out, 0);
        return;
    }

    size_t l = NTL::NumBytes(num);
    if (l > bs.size())
        bs.resize(l);

    int sgn = NTL::sign(num);
    assert(sgn == +1 || sgn == -1);

    NTL::BytesFromZZ(bs.data(), num, l);
    mpz_import(out, l, -1, 1, 0, 0, bs.data());

    if (sgn < 0)
        mpz_neg(out, out);
}

mpz_class round_to_z(const mpq_class &x)
{
    mpz_class n = x.get_num();
    mpz_class d = x.get_den();
    mpz_class q, r;
    mpz_fdiv_qr(q.get_mpz_t(), r.get_mpz_t(), n.get_mpz_t(), d.get_mpz_t());
    if (2 * r >= d)
        q += 1;
    return q;
}

// Babai最近平面算法（2维特化版）
mpz_class Babai_closest_vector(const mpz_class (&M)[2][2], const mpq_class (&G)[2][2], const mpq_class &norm0, const mpq_class &norm1, const mpz_class (&target)[2])
{
    mpz_class small[2];
    small[0] = target[0];
    small[1] = target[1];

    { // 计算点积
        mpq_class dot = 0;
        for (int j = 0; j < 2; ++j)
        {
            dot += small[j] * G[1][j];
        }

        // 计算系数并四舍五入
        mpq_class c_mpq = dot / norm1;
        mpz_class c = round_to_z(c_mpq);

        // 更新small向量
        for (int j = 0; j < 2; ++j)
        {
            small[j] -= M[1][j] * c;
        }
    }

    { // 计算点积
        mpq_class dot = 0;
        for (int j = 0; j < 2; ++j)
        {
            dot += small[j] * G[0][j];
        }

        // 计算系数并四舍五入
        mpq_class c_mpq = dot / norm0;
        mpz_class c = round_to_z(c_mpq);

        // 更新small向量
        for (int j = 0; j < 2; ++j)
        {
            small[j] -= M[0][j] * c;
        }
    }

    // 生成最终结果
    return target[1] - small[1];
}

int main()
{
    const int num_threads = 15;
    std::mutex output_mutex;

    // 初始化常量
    mpz_class c("211640773278950979056750572233151914615");
    // mpz_class c("215758704958218405648965277225764045983");
    mpz_class c0 = (c - 1) / 2;
    mpz_class c0_mod = c0 % (mpz_class(1) << nbits);
    mpz_class c0_inv;
    mpz_class mod_value = mpz_class(1) << nbits;
    mpz_invert(c0_inv.get_mpz_t(), c0_mod.get_mpz_t(), mod_value.get_mpz_t());

    // 预计算常量
    const mpz_class MOD_nbits = (mpz_class(1) << nbits) - 1;
    const mpz_class c_65 = c % (mpz_class(1) << 65);
    const mpz_class c0_64_nbits = (-c0) % (mpz_class(1) << (64 + nbits));
    const mpz_class MOD_64_nbits = (mpz_class(1) << (64 + nbits)) - 1;
    const mpz_class MOD_65 = (mpz_class(1) << 65) - 1;
    const mpz_class MOD_128 = (mpz_class(1) << 128) - 1;

    // 构建格基矩阵
    mat_ZZ M;
    M.SetDims(2, 2);
    M[0][0] = conv<ZZ>(c0.get_str().c_str());
    M[0][1] = 1;
    M[1][0] = power2_ZZ(64);
    M[1][1] = 0;
    ZZ det;
    LLL(det, M);

    mpz_class M2[2][2];
    ntl2gmp(M2[0][0].get_mpz_t(), M[0][0]);
    ntl2gmp(M2[0][1].get_mpz_t(), M[0][1]);
    ntl2gmp(M2[1][0].get_mpz_t(), M[1][0]);
    ntl2gmp(M2[1][1].get_mpz_t(), M[1][1]);

    cout << M2[0][0].get_str() << " " << M2[0][1].get_str() << endl;
    cout << M2[1][0].get_str() << " " << M2[1][1].get_str() << endl;

    // Gram-Schmidt正交化
    mpq_class G[2][2];
    G[0][0] = mpq_class(M2[0][0]);
    G[0][1] = mpq_class(M2[0][1]);
    G[1][0] = mpq_class(M2[1][0]);
    G[1][1] = mpq_class(M2[1][1]);
    mpq_class norm0 = G[0][0] * G[0][0] + G[0][1] * G[0][1];
    mpq_class mu = G[1][0] * G[0][0] + G[1][1] * G[0][1];
    mpq_class r = mu / norm0;
    G[1][0] -= r * G[0][0];
    G[1][1] -= r * G[0][1];
    mpq_class norm1 = G[1][0] * G[1][0] + G[1][1] * G[1][1];

    // 主循环（演示结构，实际范围太大）
    // const mpz_class lower_bound("-7336372553");
    const mpz_class lower_bound = -mpz_class(1) << (nbits - 1);
    const mpz_class upper_bound = (mpz_class(1) << (nbits - 1));
    // mpz_class guess_diff_k("2485992776856491703");
    cout << "lower_bound = " << lower_bound.get_str() << endl;
    cout << "upper_bound = " << upper_bound.get_str() << endl;
    vector<thread> threads;
    for (int t = 0; t < num_threads; ++t)
    {
        threads.emplace_back([&, t]()
                             {
            cout << "Thread " << t << " started." << endl;
            for (mpz_class guess_diff_k = lower_bound + t; guess_diff_k < upper_bound; guess_diff_k += num_threads)
            {
                if ((guess_diff_k & 0xFFFFFFF) == 0)
                {
                    if (guess_diff_k == 0) continue;
                    time_t time_now = chrono::system_clock::to_time_t(chrono::system_clock::now());
                    lock_guard<mutex> lock(output_mutex);
                    cout << time_now << "  diff_k = " << guess_diff_k.get_str() << endl;
                }

                // 步骤1：计算k的最后nbits位
                mpz_class k_last_bits = (guess_diff_k * c0_inv) & MOD_nbits;

                // 步骤2：计算k2的最后nbits位
                mpz_class k2_last_bits = (guess_diff_k * 2 + k_last_bits) & MOD_nbits;

                // 步骤3：计算中间位
                mpz_class k_middle_bits = (k2_last_bits ^ k_last_bits) & MOD_nbits;

                // 步骤4：构建目标向量
                mpz_class t0 = (k_middle_bits << 65) | k_last_bits;
                mpz_class t = ((c0_64_nbits * t0) & MOD_64_nbits) >> nbits;
                mpz_class target[2] = {t, 0};

                // 步骤5：运行Babai算法
                mpz_class sol = Babai_closest_vector(M2, G, norm0, norm1, target);
                if (sol < 0 || sol >> (65-nbits) != 0)
                {
                    continue; // 过滤掉不合法的解
                }

                // 步骤6：验证候选解
                mpz_class k_last_bits2 = k_last_bits | (sol << nbits);
                mpz_class k2_last_bits2 = (c_65 * k_last_bits2) & MOD_65;
                mpz_class k_first_bits = (k2_last_bits2 ^ k_last_bits2) & MOD_65;
                mpz_class guess_k = (k_first_bits << 65) | k_last_bits2;

                // 验证条件
                mpz_class lhs = (c * guess_k) & MOD_128;
                mpz_class rhs = guess_k ^ (guess_k >> 65);
                if (lhs == rhs)
                {
                    lock_guard<mutex> lock(output_mutex);
                    cout << "Find: k = " << hex << guess_k.get_str() << endl;
                    exit(0); // Terminate all threads
                }
            } });
    }

    for (auto &thread : threads)
    {
        thread.join();
    }

    return 0;
}
