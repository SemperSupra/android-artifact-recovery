#include <jni.h>
#include <cstdint>
#include <vector>

#include "payload_stats.h"

extern "C"
JNIEXPORT jlongArray JNICALL
Java_org_sempersupra_aar_golden_jni_NativePayloadStats_nativeAnalyze(
    JNIEnv* env,
    jobject,
    jbyteArray payload
) {
    const jsize size = payload == nullptr ? 0 : env->GetArrayLength(payload);
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size));

    if (size > 0) {
        env->GetByteArrayRegion(
            payload,
            0,
            size,
            reinterpret_cast<jbyte*>(bytes.data())
        );
    }

    const auto stats = aar::golden::analyze_payload(bytes.data(), bytes.size());

    const jlong values[6] = {
        static_cast<jlong>(stats.fnv1a64),
        static_cast<jlong>(stats.length),
        static_cast<jlong>(stats.zero_count),
        static_cast<jlong>(stats.ascii_count),
        static_cast<jlong>(stats.longest_run),
        static_cast<jlong>(stats.distinct_bytes),
    };

    jlongArray result = env->NewLongArray(6);
    if (result == nullptr) {
        return nullptr;
    }
    env->SetLongArrayRegion(result, 0, 6, values);
    return result;
}
