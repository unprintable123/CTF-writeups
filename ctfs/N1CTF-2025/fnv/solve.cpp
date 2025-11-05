#include <iostream>
#include <vector>
#include <cmath>
#include <random>
#include <algorithm>
#include <map>
#include <memory>
#include <cassert>

using namespace std;

#if defined(__GNUG__)
typedef unsigned __int128 uint128_t;
typedef __int128 int128_t;
std::ostream &operator<<(std::ostream &os, uint128_t value)
{
    if (value == 0)
        return os << "0";
    std::string s;
    uint128_t temp = value;
    while (temp > 0)
    {
        s += (char)(temp % 10 + '0');
        temp /= 10;
    }
    std::reverse(s.begin(), s.end());
    return os << s;
}

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

std::istream &operator>>(std::istream &in, uint128_t &value)
{
    value = 0;
    char c;
    bool found_digit = false;

    if (!in.get(c))
    {
        in.setstate(std::ios::failbit);
        return in;
    }

    do
    {
        if (c >= '0' && c <= '9')
        {
            found_digit = true;
            uint128_t digit = c - '0';
            value *= 10;

            value += digit;
        }
        else if (found_digit)
        {
            in.unget();
            break;
        }
        else if (!std::isspace(c))
        {
            in.unget();
            in.setstate(std::ios::failbit);
            return in;
        }

        if (!in.get(c))
            break;
    } while (true);

    if (!found_digit)
    {
        in.setstate(std::ios::failbit);
    }

    return in;
}
#else
// For MSVC which does not support __int128
// Only used for intellisense in Windows
typedef unsigned long long uint128_t;
typedef long long int128_t;
#endif

uint128_t a, b, c, x, a_inv, target;

uint128_t fnv_hash(uint128_t x0, string message)
{
    // cout << "x0: " << x0 << endl;
    uint128_t h = x0;
    for (char ch : message)
    {
        for (int i = 7; i >= 0; i--)
        {
            uint8_t byte = (ch >> i) & 1;
            h = h * a + b + byte;
            h = h ^ c;
            // cout << int(byte) << "  " << (ch) << "  " << h << endl;
        }
    }
    return h;
}

uint128_t fnv_hash_inv(uint128_t xn, string message)
{
    uint128_t h = xn;
    for (int idx = (int)message.size() - 1; idx >= 0; idx--)
    {
        char ch = message[idx];
        for (int i = 0; i < 8; i++)
        {
            uint8_t byte = (ch >> i) & 1;
            h = h ^ c;
            h = (h - b - byte) * a_inv;
        }
    }
    return h;
}

string find_next_start_to_target(string prefix, size_t cur_bits, std::shared_ptr<vector<string>> &target_to_target)
{
    uint128_t mask = (uint128_t(1ULL) << cur_bits) - 1;
    if (cur_bits >= 128)
    {
        mask = uint128_t(-1);
    }
    uint128_t cur_hash = fnv_hash(x, prefix);
    // enumurate all target_to_target
    auto s = target_to_target->size();
    for (size_t i = 0; i < s; i++)
    {
        string suffix = (*target_to_target)[i];
        uint128_t next_target = fnv_hash(cur_hash, suffix);
        if ((next_target & mask) == (target & mask))
        {
            return prefix + suffix;
        }
    }
    cout << "No valid start_to_target found!" << endl;
    exit(1);
}

void find_next_target_to_target(size_t cur_bits, std::shared_ptr<vector<string>> &target_to_target, std::shared_ptr<vector<string>> &target_to_target_new)
{
    std::shared_ptr<multimap<uint128_t, string>> look_uptable1 = std::make_shared<multimap<uint128_t, string>>();
    std::shared_ptr<multimap<uint128_t, string>> look_uptable2 = std::make_shared<multimap<uint128_t, string>>();
    uint128_t mask = (uint128_t(1ULL) << cur_bits) - 1;
    for (const string &msg : *target_to_target)
    {
        uint128_t mid1 = fnv_hash(target, msg) & mask;
        look_uptable1->emplace(mid1, msg);
        uint128_t mid2 = fnv_hash_inv(target, msg) & mask;
        look_uptable2->emplace(mid2, msg);
    }

    // find collisions using multimap equal_range
    for (auto it = look_uptable1->begin(); it != look_uptable1->end();)
    {
        auto range1 = look_uptable1->equal_range(it->first);
        auto range2 = look_uptable2->equal_range(it->first);

        if (range2.first != range2.second)
        {
            for (auto it1 = range1.first; it1 != range1.second; ++it1)
            {
                for (auto it2 = range2.first; it2 != range2.second; ++it2)
                {
                    target_to_target_new->push_back(it1->second + it2->second);
                }
                if (target_to_target_new->size() >= 1048576)
                    break;
            }
        }

        it = range1.second; // advance past this key's block
        if (target_to_target_new->size() >= 1048576)
            break;
    }
}

int main()
{
    cout << "Enter parameters a, b, c, x, a_inv:" << endl;
    cin >> a >> b >> c >> x >> a_inv;

    if (a * a_inv != 1)
    {
        cerr << "Invalid parameters!" << endl;
        return 1;
    }

    assert(fnv_hash_inv(fnv_hash(x, "test"), "test") == x);
    cout << "test:" << fnv_hash(x, "test") << endl;

    cout << "Enter target hash value:" << endl;
    cin >> target;

    std::shared_ptr<vector<string>> target_to_target = std::make_shared<vector<string>>();
    // push 2**20 messages of length 3
    for (uint32_t i = 0; i < 65536; i++)
    {
        string msg = "";
        for (int j = 0; j < 2; j++)
        {
            msg += char((i >> (j * 8)) & 0xFF);
        }
        target_to_target->push_back(msg);
    }
    size_t cur_bits = 0;
    string start_to_target = "";
    while (cur_bits < 128)
    {
        if (cur_bits > 0)
            cur_bits += 17;
        else
            cur_bits = 12;
        cout << "Building target_to_target for bits " << cur_bits << "..." << endl;
        start_to_target = find_next_start_to_target(start_to_target, cur_bits, target_to_target);
        {
            uint128_t verify_hash = fnv_hash(x, start_to_target);
            uint128_t mask = (uint128_t(1ULL) << cur_bits) - 1;
            if ((verify_hash & mask) != (target & mask))
            {
                cout << "Verification failed!" << endl;
                exit(1);
            }
        }
        if (cur_bits >= 128)
            break;
        std::shared_ptr<vector<string>> new_target_to_target = std::make_shared<vector<string>>();
        find_next_target_to_target(cur_bits, target_to_target, new_target_to_target);
        target_to_target = new_target_to_target;
    }
    cout << "Final message:";
    // print start_to_target in hex
    for (char ch : start_to_target)
    {
        printf("%02x", (unsigned char)ch);
    }
    cout << endl;
    return 0;
}
