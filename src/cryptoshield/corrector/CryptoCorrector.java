package cryptoshield.corrector;

import cryptoshield.policy.SecurityPolicy;
import cryptoshield.policy.ViolationRecord;

/**
 * CryptoShield Auto-Corrector
 * Maps insecure crypto configurations to their secure equivalents.
 * Part of the fixed-point enforcement loop (Component 3).
 */
public class CryptoCorrector {

    /**
     * Correct an insecure cipher transformation.
     * @param original  e.g. "DES", "AES/ECB/NoPadding"
     * @param rec       violation record to annotate
     * @return          secure replacement, e.g. "AES/GCM/NoPadding"
     */
    public String correctCipher(String original, ViolationRecord rec) {
        String corrected = SecurityPolicy.correctCipher(original);
        rec.setCorrectedAlgorithm(corrected);
        rec.addTrace("Corrector: " + original + " → " + corrected);
        return corrected;
    }

    /**
     * Correct an insecure hash algorithm.
     * @param original  e.g. "MD5", "SHA-1"
     * @param rec       violation record to annotate
     * @return          secure replacement, e.g. "SHA-256"
     */
    public String correctHash(String original, ViolationRecord rec) {
        String corrected = SecurityPolicy.correctHash(original);
        rec.setCorrectedAlgorithm(corrected);
        rec.addTrace("Corrector: " + original + " → " + corrected);
        return corrected;
    }
}
