#include <iostream>  // For input/output operations (e.g., std::cout)
#include <vector>    // For std::vector
#include <algorithm> // For std::sort, std::lower_bound
#include <map>       // For std::map to store sums and their corresponding subsets
#include <memory>
#include <cmath> // For std::pow

// g++ -O3 solve.cpp -o solve && ./solve

typedef __int128 int128_t;
std::ostream &operator<<(std::ostream &os, int128_t val)
{
    std::string result;
    bool is_negative = val < 0;
    if (is_negative)
    {
        val *= -1;
    }

    do
    {
        result.push_back((val % 10) + '0');
        val /= 10;
    } while (val != 0);

    if (is_negative)
    {
        result.push_back('-');
    }

    std::reverse(result.begin(), result.end());
    return (os << result);
}

typedef std::pair<int64_t, int64_t> vec2;
typedef std::tuple<int64_t, int64_t, int128_t> vec3;

std::vector<vec2> pairs;

void gen1(int digits, std::shared_ptr<std::vector<vec3>> &result)
{
    if (digits == 1)
    {
        for (const auto &pair : pairs)
        {
            int64_t a = pair.first;
            int64_t b = pair.second;
            result->emplace_back(a, b, a * b);
        }
        return;
    }

    int128_t mul = std::round(std::pow(10, digits - 1));
    int128_t mul1 = std::round(std::pow(10, digits));
    int128_t mul2 = mul * mul;
    if (mul % 10 != 0 || mul1 % 10 != 0 || mul2 % 10 != 0)
    {
        std::cerr << "Error: mul is not a multiple of 10" << std::endl;
        exit(1);
    }

    std::shared_ptr<std::vector<vec3>> result0 = std::make_shared<std::vector<vec3>>();
    gen1(digits - 1, result0);
    for (const auto &item : *result0)
    {
        int64_t x = std::get<0>(item);
        int64_t y = std::get<1>(item);
        int128_t xy_mul = std::get<2>(item);
        for (const auto &pair : pairs)
        {
            int64_t a = pair.first;
            int64_t b = pair.second;
            int128_t x2 = a * mul + x;
            int128_t y2 = b * mul + y;
            int128_t xy_mul2 = xy_mul + (a * b) * mul2;
            if ((x2 * y2 - xy_mul2) % mul1 == 0)
            {
                result->emplace_back(x2, y2, xy_mul2);
            }
        }
    }
}

void gen2(int digits, std::shared_ptr<std::vector<vec3>> &result)
{
    if (digits == 1)
    {
        for (const auto &pair : pairs)
        {
            int64_t a = pair.first;
            int64_t b = pair.second;
            for (int64_t i = 1; i < 10; i++)
            {
                int64_t x = 10 * i + a;
                int64_t y = b;
                result->emplace_back(x, y, 100 * i + a * b);
            }
        }
        return;
    }

    std::shared_ptr<std::vector<vec3>> result0 = std::make_shared<std::vector<vec3>>();
    gen2(digits - 1, result0);
    for (const auto &item : *result0)
    {
        int64_t x = std::get<0>(item);
        int64_t y = std::get<1>(item);
        int128_t xy_mul = std::get<2>(item);
        for (const auto &pair : pairs)
        {
            int64_t a = pair.first;
            int64_t b = pair.second;
            int128_t x2 = 10 * x + a;
            int128_t y2 = 10 * y + b;
            int128_t xy_mul2 = 100 * xy_mul + a * b;
            int128_t lower_bound = x2 * y2;
            int128_t upper_bound = (x2 + 1) * (y2 + 1);
            if (lower_bound <= xy_mul2 && xy_mul2 < upper_bound)
            {
                result->emplace_back(x2, y2, xy_mul2);
            }
        }
    }
}

#define M1 2
#define M2 3
#define M3 2

int main()
{
    for (int64_t i = 1; i < 10; i++)
        for (int64_t j = 1; j < 10; j++)
        {
            if (i * j >= 10)
            {
                pairs.push_back({i, j});
            }
        }

    std::shared_ptr<std::vector<vec3>> result1 = std::make_shared<std::vector<vec3>>();
    std::shared_ptr<std::vector<vec3>> result2 = std::make_shared<std::vector<vec3>>();
    gen1(M2 + M3, result1);

    std::cout << "Size1: " << result1->size() << std::endl;

    int128_t last_M3_digits = std::round(std::pow(10, M3));
    int128_t last_M3_digits2 = last_M3_digits * last_M3_digits;
    int128_t last_M2_digits = std::round(std::pow(10, M2));

    std::shared_ptr<std::map<uint64_t, std::vector<vec3>>> result_map = std::make_shared<std::map<uint64_t, std::vector<vec3>>>();
    for (const auto &item : *result1)
    {
        int64_t x = std::get<0>(item);
        int64_t y = std::get<1>(item);
        int128_t xy_mul = std::get<2>(item);
        uint64_t x2 = x / last_M3_digits;
        uint64_t y2 = y / last_M3_digits;
        uint64_t key = (x2 << 32) | y2;
        if (result_map->find(key) == result_map->end())
        {
            (*result_map)[key] = std::vector<vec3>();
        }
        (*result_map)[key].emplace_back(x, y, xy_mul);
    }
    result1.reset();
    std::cout << "Finished processing map" << std::endl;

    gen2(M1 + M2, result2);
    std::cout << "Size2: " << result2->size() << std::endl;
    for (const auto &item : *result2)
    {
        int64_t x = std::get<0>(item);
        int64_t y = std::get<1>(item);
        int128_t xy_mul = std::get<2>(item);
        uint64_t x2 = x % last_M2_digits;
        uint64_t y2 = y % last_M2_digits;
        uint64_t key = (x2 << 32) | y2;
        auto it = result_map->find(key);
        if (it != result_map->end())
        {
            for (const auto &pair : it->second)
            {
                int64_t x1 = std::get<0>(pair);
                int64_t y1 = std::get<1>(pair);
                int128_t xy_mul1 = std::get<2>(pair);
                int128_t x_final = (int128_t)x * last_M3_digits + (int128_t)x1 % last_M3_digits;
                int128_t y_final = (int128_t)y * last_M3_digits + (int128_t)y1 % last_M3_digits;
                int128_t xy_mul_final = xy_mul * last_M3_digits2 + xy_mul1 % last_M3_digits2;
                if (x_final * y_final == xy_mul_final)
                {
                    std::cout << "Found: x=" << x_final << ", y=" << y_final << ", x*y=" << xy_mul_final << std::endl;
                }
            }
        }
    }
}
