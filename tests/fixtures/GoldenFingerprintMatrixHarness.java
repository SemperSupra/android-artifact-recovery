import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.sempersupra.aar.golden.kotlin.GoldenRecordFingerprint;

/** Independent public source-known behavior vectors (not JADX-derived). */
public final class GoldenFingerprintMatrixHarness {
    public static void main(String[] args) throws Exception {
        String[] vectors = new String[] {
            "",
            " # only a comment\n\n",
            "invalid without equals\n",
            "KEY=one\nkey=two\n",
            " B = two   words\nA= alpha\n",
            "Ü = Grüße\nภาษาไทย=ทดสอบ\n",
            "=empty key\nok=present\n",
            "#skip\nA=1\ninvalid\nA=2\n",
            "spaced = \n spaced =    value\twith\t tabs  \n",
            "b=2\na=1\nb=1\n"
        };
        for (int i = 0; i < vectors.length; i++) {
            GoldenRecordFingerprint.Result r =
                GoldenRecordFingerprint.INSTANCE.fingerprint(vectors[i]);
            System.out.println(
                "case=" + i +
                "|canonical_b64=" + Base64.getEncoder().encodeToString(
                    r.getCanonical().getBytes(StandardCharsets.UTF_8)) +
                "|sha256=" + r.getSha256() +
                "|records=" + r.getRecordCount() +
                "|keys=" + r.getUniqueKeyCount()
            );
        }
    }
}
