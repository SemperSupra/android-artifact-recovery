package org.sempersupra.aar.golden.methodology;

/** Source-known public D8/JADX differential: nontrivial branches and switch. */
public final class BranchAndFold {
    private BranchAndFold() {}

    public static int compute(int value) {
        int n = value < 0 ? -value : value;
        switch (n % 4) {
            case 0:
                return n + 3;
            case 1:
                return 7 * n;
            case 2:
                return (n ^ 0x55) + 1;
            default:
                return n - 9;
        }
    }

    public static void main(String[] args) {
        int[] inputs = { -4, 5, 6, 7, 12, 21 };
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < inputs.length; i++) {
            if (i != 0) {
                result.append('|');
            }
            result.append(compute(inputs[i]));
        }
        System.out.println(result.toString());
    }
}
