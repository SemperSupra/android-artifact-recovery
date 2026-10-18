# Public authored Kotlin fixture. Retain class/method behavior for golden
# analysis, but permit R8 to rename their identifiers.
# Do not give generated mapping.txt to blind recovery actors.
-keep,allowobfuscation class org.sempersupra.aar.golden.kotlin.GoldenRecordFingerprint {
    *;
}
