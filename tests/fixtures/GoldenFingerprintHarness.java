import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.sempersupra.aar.golden.kotlin.GoldenRecordFingerprint;

public final class GoldenFingerprintHarness {
    public static void main(String[] args) throws Exception {
        String input =
            "# AAR sample\n" +
            " Beta = two   words\n" +
            "alpha= one\n" +
            "beta=second\n";

        GoldenRecordFingerprint.Result result =
            GoldenRecordFingerprint.INSTANCE.fingerprint(input);

        System.out.println(
            "canonical_b64=" +
            Base64.getEncoder().encodeToString(
                result.getCanonical().getBytes(StandardCharsets.UTF_8)
            )
        );
        System.out.println("sha256=" + result.getSha256());
        System.out.println("record_count=" + result.getRecordCount());
        System.out.println("unique_key_count=" + result.getUniqueKeyCount());
    }
}
