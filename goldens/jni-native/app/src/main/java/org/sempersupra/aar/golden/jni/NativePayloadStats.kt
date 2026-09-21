package org.sempersupra.aar.golden.jni

data class PayloadStats(
    val fnv1a64: ULong,
    val length: Int,
    val zeroCount: Int,
    val asciiCount: Int,
    val longestRun: Int,
    val distinctBytes: Int,
)

object NativePayloadStats {
    init {
        System.loadLibrary("aar_golden_jni")
    }

    private external fun nativeAnalyze(payload: ByteArray): LongArray

    fun analyze(payload: ByteArray): PayloadStats {
        val raw = nativeAnalyze(payload)
        require(raw.size == 6) { "native result must contain six fields" }
        return PayloadStats(
            fnv1a64 = raw[0].toULong(),
            length = raw[1].toInt(),
            zeroCount = raw[2].toInt(),
            asciiCount = raw[3].toInt(),
            longestRun = raw[4].toInt(),
            distinctBytes = raw[5].toInt(),
        )
    }
}
