#include <array>
#include <cstdint>
#include <cstdlib>
#include <iostream>

#include "../app/src/main/cpp/payload_stats.h"

int main() {
    const std::array<std::uint8_t, 6> sample = {
        0x00, 0x41, 0x41, 0x41, 0x7f, 0xff
    };

    const auto stats = aar::golden::analyze_payload(sample.data(), sample.size());

    const bool ok =
        stats.fnv1a64 == 0x0f73bd21e3c006f6ull &&
        stats.length == 6 &&
        stats.zero_count == 1 &&
        stats.ascii_count == 3 &&
        stats.longest_run == 3 &&
        stats.distinct_bytes == 4;

    if (!ok) {
        std::cerr
            << "fnv1a64=" << std::hex << stats.fnv1a64 << std::dec
            << " length=" << stats.length
            << " zero_count=" << stats.zero_count
            << " ascii_count=" << stats.ascii_count
            << " longest_run=" << stats.longest_run
            << " distinct_bytes=" << stats.distinct_bytes
            << "\n";
        return EXIT_FAILURE;
    }

    std::cout << "golden-native-vector: PASS\n";
    return EXIT_SUCCESS;
}
