package org.sempersupra.aar.golden.kotlin

import java.security.MessageDigest

/**
 * Small useful deterministic workload for recovery experiments.
 *
 * Canonicalizes key=value records and fingerprints the canonical byte stream.
 * The behavior is deliberately independent of Android framework APIs so the
 * same semantic oracle can run in local unit tests and recovered implementations.
 */
object GoldenRecordFingerprint {
    data class Result(
        val canonical: String,
        val sha256: String,
        val recordCount: Int,
        val uniqueKeyCount: Int,
    )

    fun canonicalize(input: String): String {
        val records = input.lineSequence()
            .map { it.trim() }
            .filter { it.isNotEmpty() && !it.startsWith("#") }
            .mapNotNull { line ->
                val split = line.indexOf('=')
                if (split < 0) return@mapNotNull null
                val key = line.substring(0, split).trim().lowercase()
                if (key.isEmpty()) return@mapNotNull null
                val value = line.substring(split + 1)
                    .trim()
                    .split(Regex("\\s+"))
                    .filter { it.isNotEmpty() }
                    .joinToString(" ")
                key to value
            }
            .sortedWith(compareBy<Pair<String, String>>({ it.first }, { it.second }))
            .toList()

        if (records.isEmpty()) return ""
        return records.joinToString(separator = "\n", postfix = "\n") { (key, value) ->
            "$key=$value"
        }
    }

    fun fingerprint(input: String): Result {
        val canonical = canonicalize(input)
        val digest = MessageDigest.getInstance("SHA-256")
            .digest(canonical.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }

        val records = canonical.lineSequence().filter { it.isNotEmpty() }.toList()
        val uniqueKeys = records.map { it.substringBefore('=') }.toSet().size
        return Result(
            canonical = canonical,
            sha256 = digest,
            recordCount = records.size,
            uniqueKeyCount = uniqueKeys,
        )
    }
}
