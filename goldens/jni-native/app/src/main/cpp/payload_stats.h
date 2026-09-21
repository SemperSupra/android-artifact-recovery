#pragma once

#include <cstddef>
#include <cstdint>

namespace aar::golden {

struct PayloadStats {
    std::uint64_t fnv1a64;
    std::uint32_t length;
    std::uint32_t zero_count;
    std::uint32_t ascii_count;
    std::uint32_t longest_run;
    std::uint32_t distinct_bytes;
};

PayloadStats analyze_payload(const std::uint8_t* data, std::size_t size) noexcept;

}  // namespace aar::golden
