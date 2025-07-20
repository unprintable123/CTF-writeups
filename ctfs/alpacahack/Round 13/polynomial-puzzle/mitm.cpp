#include <iostream>  // For input/output operations (e.g., std::cout)
#include <vector>    // For std::vector
#include <algorithm> // For std::sort, std::lower_bound
#include <map>       // For std::map to store sums and their corresponding subsets
#include <memory>

typedef std::pair<uint64_t, uint64_t> vec2;
uint64_t p;

void generateSubsetSums(const std::vector<std::vector<vec2>> &subsets, std::shared_ptr<std::map<vec2, uint64_t>> &sumMap)
{
    if (subsets.size() == 1)
    {
        // Base case: only one subset, initialize sumMap with its elements
        for (uint64_t i = 0; i < 6; ++i)
        {
            vec2 num = subsets[0][i];
            (*sumMap)[num] = i;
        }
        return;
    }

    std::shared_ptr<std::map<vec2, uint64_t>> localSumMap = std::make_shared<std::map<vec2, uint64_t>>();
    uint64_t subsetCount = subsets.size();

    // Use all subsets except the last one
    std::vector<std::vector<vec2>> slicedSubsets(subsets.begin(), subsets.end() - 1);
    generateSubsetSums(slicedSubsets, localSumMap);

    auto lastSubset = subsets.back();

#pragma omp parallel for
    for (uint64_t i = 0; i < 6; ++i)
    {
        auto num = lastSubset[i];
        for (const auto &pair : *localSumMap)
        {
            vec2 newVec = {(pair.first.first + num.first) % p, (pair.first.second + num.second) % p};
            uint64_t newSum = (pair.second << 3) | i;

#pragma omp critical
            {
                (*sumMap)[newVec] = newSum;
            }
        }
    }
}

int main()
{
    std::cin >> p;
    std::cout << "P: " << p << std::endl;
    std::vector<std::vector<vec2>> subsets;

    for (uint64_t i = 0; i < 23; ++i)
    {
        std::cout << "Input subset " << i + 1 << " (6 pairs of numbers): " << std::endl;
        std::vector<vec2> subset;
        for (uint64_t j = 0; j < 6; ++j)
        {
            uint64_t x, y;
            std::cin >> x >> y;
            subset.emplace_back(x, y);
        }
        subsets.push_back(subset);
    }

    // print the input subsets for debugging
    for (const auto &subset : subsets)
    {
        for (const auto &num : subset)
        {
            std::cout << "(" << num.first << ", " << num.second << ") ";
        }
        std::cout << std::endl;
    }

    std::shared_ptr<std::map<vec2, uint64_t>> sumMap1 = std::make_shared<std::map<vec2, uint64_t>>();
    std::shared_ptr<std::map<vec2, uint64_t>> sumMap2 = std::make_shared<std::map<vec2, uint64_t>>();
    std::shared_ptr<std::map<vec2, uint64_t>> sumMap3 = std::make_shared<std::map<vec2, uint64_t>>();

    std::vector<std::vector<vec2>> subsets1(subsets.begin(), subsets.begin() + 6);
    std::vector<std::vector<vec2>> subsets2(subsets.begin() + 6, subsets.begin() + 12);
    std::vector<std::vector<vec2>> subsets3(subsets.begin() + 12, subsets.end());

    generateSubsetSums(subsets1, sumMap1);
    std::cout << "Generated subset sums for first 6 subsets." << std::endl;
    generateSubsetSums(subsets2, sumMap2);
    std::cout << "Generated subset sums for next 6 subsets." << std::endl;
    generateSubsetSums(subsets3, sumMap3);
    std::cout << "Generated subset sums for last 11 subsets." << std::endl;

    // Convert map to vector for OpenMP parallelization
    std::vector<std::pair<vec2, uint64_t>> sumMap1Vec(sumMap1->begin(), sumMap1->end());

#pragma omp parallel for
    for (size_t i = 0; i < sumMap1Vec.size(); ++i)
    {
        if (i % 100 == 0)
        {
            std::cout << "Processing sumMap1Vec index: " << i << std::endl;
        }
        const auto &pair1 = sumMap1Vec[i];
        // Your parallel code here
        for (const auto &pair2 : *sumMap2)
        {
            vec2 newVec = {p - ((pair1.first.first + pair2.first.first) % p), p - ((pair1.first.second + pair2.first.second) % p)};
            if (sumMap3->find(newVec) != sumMap3->end())
            {
                auto map3_val = (*sumMap3)[newVec];
                std::cout << "Found matching sum: " << pair1.second << " " << pair2.second << " " << map3_val << std::endl;
            }
        }
    }
}
