package org.sempersupra.aar.golden.kotlin

import org.junit.Assert.assertEquals
import org.junit.Test

class GoldenRecordFingerprintTest {
    @Test
    fun canonicalizesAndFingerprintsKnownVector() {
        val input = """
            # AAR sample
             Beta = two   words
            alpha= one
            beta=second
        """.trimIndent()

        val result = GoldenRecordFingerprint.fingerprint(input)

        assertEquals(
            "alpha=one\nbeta=second\nbeta=two words\n",
            result.canonical,
        )
        assertEquals(
            "1c94d71cfe92db05be151ffe400360ce0b955ff16e6e40f68c4db54b3d98c73f",
            result.sha256,
        )
        assertEquals(3, result.recordCount)
        assertEquals(2, result.uniqueKeyCount)
    }

    @Test
    fun ignoresCommentsBlankLinesAndMalformedRecords() {
        val input = """
            # comment

            malformed
            =no-key
            z =  value
        """.trimIndent()

        val result = GoldenRecordFingerprint.fingerprint(input)
        assertEquals("z=value\n", result.canonical)
        assertEquals(1, result.recordCount)
        assertEquals(1, result.uniqueKeyCount)
    }
}
