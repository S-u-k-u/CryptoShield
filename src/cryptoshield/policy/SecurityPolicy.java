package cryptoshield.policy;

import java.util.*;

/**
 * CryptoShield Security Policy Engine
 * Defines approved algorithms and violation correction mappings.
 * Based on: NIST SP 800-175B, CWE-327, CWE-328, CWE-338
 */
public class SecurityPolicy {

    // ── Approved algorithm sets ──────────────────────────────────────────
    public static final Set<String> SECURE_CIPHERS = new HashSet<>(Arrays.asList(
            "AES/GCM/NoPadding",
            "AES/CBC/PKCS5Padding",
            "AES/CBC/PKCS7Padding",
            "ChaCha20-Poly1305"));

    public static final Set<String> SECURE_HASHES = new HashSet<>(Arrays.asList(
            "SHA-256", "SHA-384", "SHA-512",
            "SHA3-256", "SHA3-384", "SHA3-512",
            "SHA-256/with-ECDSA"));

    public static final Set<Integer> SECURE_KEY_SIZES = new HashSet<>(Arrays.asList(128, 192, 256));

    // ── CWE mappings ─────────────────────────────────────────────────────
    public static final Map<String, String> ALGORITHM_CWE = new HashMap<>();
    static {
        ALGORITHM_CWE.put("DES", "CWE-327");
        ALGORITHM_CWE.put("3DES", "CWE-327");
        ALGORITHM_CWE.put("DESede", "CWE-327");
        ALGORITHM_CWE.put("RC2", "CWE-327");
        ALGORITHM_CWE.put("RC4", "CWE-327");
        ALGORITHM_CWE.put("Blowfish", "CWE-327");
        ALGORITHM_CWE.put("AES/ECB", "CWE-327");
        ALGORITHM_CWE.put("MD5", "CWE-328");
        ALGORITHM_CWE.put("MD4", "CWE-328");
        ALGORITHM_CWE.put("SHA-1", "CWE-328");
        ALGORITHM_CWE.put("SHA1", "CWE-328");
        ALGORITHM_CWE.put("CONSTANT_IV", "CWE-329");
        ALGORITHM_CWE.put("HARDCODED_SEED", "CWE-338");
        ALGORITHM_CWE.put("SMALL_KEY", "CWE-326");
    }

    // ── Correction map: insecure → secure ────────────────────────────────
    public static final Map<String, String> CIPHER_CORRECTIONS = new LinkedHashMap<>();
    static {
        CIPHER_CORRECTIONS.put("DES", "AES/GCM/NoPadding");
        CIPHER_CORRECTIONS.put("DESede", "AES/GCM/NoPadding");
        CIPHER_CORRECTIONS.put("3DES", "AES/GCM/NoPadding");
        CIPHER_CORRECTIONS.put("AES/ECB/NoPadding", "AES/GCM/NoPadding");
        CIPHER_CORRECTIONS.put("AES/ECB/PKCS5Padding", "AES/GCM/NoPadding");
        CIPHER_CORRECTIONS.put("AES", "AES/GCM/NoPadding");
        CIPHER_CORRECTIONS.put("RC2", "AES/GCM/NoPadding");
        CIPHER_CORRECTIONS.put("RC4", "ChaCha20-Poly1305");
        CIPHER_CORRECTIONS.put("Blowfish", "AES/GCM/NoPadding");
    }

    public static final Map<String, String> HASH_CORRECTIONS = new LinkedHashMap<>();
    static {
        HASH_CORRECTIONS.put("MD5", "SHA-256");
        HASH_CORRECTIONS.put("MD4", "SHA-256");
        HASH_CORRECTIONS.put("SHA-1", "SHA-256");
        HASH_CORRECTIONS.put("SHA1", "SHA-256");
        HASH_CORRECTIONS.put("SHA", "SHA-256");
    }

    // ── Thresholds ────────────────────────────────────────────────────────
    public static final double MIN_IV_ENTROPY = 7.0; // bits/byte
    public static final int MAX_ITERATIONS = 5;
    public static final int MIN_AES_KEY_BITS = 128;
    public static final int MIN_RSA_KEY_BITS = 2048;

    /**
     * Returns true if the given cipher transformation is secure.
     */
    public static boolean isCipherSecure(String transformation) {
        if (transformation == null)
            return false;
        String upper = transformation.toUpperCase();
        // Check ECB explicitly
        if (upper.contains("ECB"))
            return false;
        // Check base algorithm
        for (String insecure : CIPHER_CORRECTIONS.keySet()) {
            if (upper.equals(insecure.toUpperCase()))
                return false;
        }
        for (String secure : SECURE_CIPHERS) {
            if (upper.equals(secure.toUpperCase()))
                return true;
        }
        return false;
    }

    public static boolean isHashSecure(String algorithm) {
        if (algorithm == null)
            return false;
        for (String secure : SECURE_HASHES) {
            if (secure.equalsIgnoreCase(algorithm))
                return true;
        }
        return false;
    }

    public static String correctCipher(String transformation) {
        if (transformation == null)
            return "AES/GCM/NoPadding";
        String upper = transformation.toUpperCase();
        for (Map.Entry<String, String> e : CIPHER_CORRECTIONS.entrySet()) {
            if (upper.equals(e.getKey().toUpperCase()) || upper.contains(e.getKey().toUpperCase())) {
                return e.getValue();
            }
        }
        // ECB fallback
        if (upper.contains("ECB"))
            return "AES/GCM/NoPadding";
        return "AES/GCM/NoPadding";
    }

    public static String correctHash(String algorithm) {
        if (algorithm == null)
            return "SHA-256";
        String correction = HASH_CORRECTIONS.get(algorithm.toUpperCase());
        return correction != null ? correction : HASH_CORRECTIONS.getOrDefault(algorithm, "SHA-256");
    }

    public static String getCwe(String algorithm) {
        if (algorithm == null)
            return "CWE-327";
        for (Map.Entry<String, String> e : ALGORITHM_CWE.entrySet()) {
            if (algorithm.toUpperCase().contains(e.getKey().toUpperCase())) {
                return e.getValue();
            }
        }
        return "CWE-327";
    }
}
