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
