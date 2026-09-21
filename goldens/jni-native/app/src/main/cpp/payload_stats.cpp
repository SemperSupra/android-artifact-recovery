#include "payload_stats.h"

#include <array>
#include <algorithm>

namespace aar::golden {

PayloadStats analyze_payload(const std::uint8_t* data, std::size_t size) noexcept {
    constexpr std::uint64_t kOffset = 14695981039346656037ull;
    constexpr std::uint64_t kPrime = 1099511628211ull;

    PayloadStats out{};
    out.fnv1a64 = kOffset;
    out.length = static_cast<std::uint32_t>(size);

    std::array<bool, 256> seen{};
    std::uint32_t current_run = 0;
    std::uint8_t previous = 0;

    for (std::size_t i = 0; i < size; ++i) {
        const std::uint8_t value = data[i];

        out.fnv1a64 ^= value;
        out.fnv1a64 *= kPrime;

        if (value == 0) {
            ++out.zero_count;
        }
        if (value >= 0x20 && value <= 0x7e) {
            ++out.ascii_count;
        }
        if (!seen[value]) {
            seen[value] = true;
            ++out.distinct_bytes;
        }

        if (i == 0 || value != previous) {
            current_run = 1;
            previous = value;
        } else {
            ++current_run;
        }
        out.longest_run = std::max(out.longest_run, current_run);
    }

    return out;
}

}  // namespace aar::golden
