package cryptoshield.agent;

/**
 * Shannon entropy calculator for IV and key material analysis.
 * H(X) = -sum(p(x) * log2(p(x)))
 * 
 * Interpretation:
 *   < 3.0 bits/byte  → constant or near-constant  (DANGEROUS)
 *   3.0–5.0           → low randomness              (SUSPICIOUS)
 *   5.0–7.0           → moderate randomness
 *   > 7.0 bits/byte  → high randomness              (SECURE)
 *   ~7.99             → near-perfect random (like /dev/urandom output)
 */
public class EntropyCalculator {

    public static double shannonEntropy(byte[] data) {
        if (data == null || data.length == 0) return 0.0;

        int[] freq = new int[256];
        for (byte b : data) freq[b & 0xFF]++;

        double entropy = 0.0;
        double len = data.length;
        for (int f : freq) {
            if (f > 0) {
                double p = f / len;
                entropy -= p * (Math.log(p) / Math.log(2));
            }
        }
        return entropy;
    }

    public static String classify(double entropy) {
        if (entropy < 1.0)  return "CONSTANT";
        if (entropy < 3.0)  return "LOW";
        if (entropy < 5.0)  return "MODERATE";
        if (entropy < 7.0)  return "GOOD";
        return "SECURE";
    }

    public static boolean isSufficientlyRandom(byte[] data) {
        return shannonEntropy(data) >= 7.0;
    }

    /** Format for display in certificates */
    public static String format(double entropy) {
        return String.format("%.4f bits/byte [%s]", entropy, classify(entropy));
    }
}
