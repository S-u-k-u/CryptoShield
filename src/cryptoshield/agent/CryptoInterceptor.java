package cryptoshield.agent;

import cryptoshield.policy.SecurityPolicy;
import cryptoshield.policy.ViolationRecord;
import cryptoshield.policy.ViolationRecord.ViolationType;
import cryptoshield.corrector.CryptoCorrector;
import cryptoshield.verifier.ConvergenceVerifier;
import cryptoshield.certificate.CertificateGenerator;
import cryptoshield.ml.MLBridge;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * CryptoShield Interception Layer
 *
 * Provides drop-in replacement methods for:
 * - Cipher.getInstance()
 * - MessageDigest.getInstance()
 * - SecureRandom seeding
 *
 * Usage in target application:
 * Replace: Cipher c = Cipher.getInstance("DES");
 * With: Cipher c = CryptoInterceptor.getCipher("DES", MyClass.class);
 */
public class CryptoInterceptor {

    private static final List<ViolationRecord> eventLog = new CopyOnWriteArrayList<>();
    private static final AtomicInteger idCounter = new AtomicInteger(1000);
    private static MLBridge mlBridge = null;
    private static boolean mlEnabled = false;

    static {
        // Try to connect to ML service on startup
        try {
            mlBridge = new MLBridge();
            mlEnabled = mlBridge.isAvailable();
            if (mlEnabled) {
                log("ML bridge connected - confidence scoring active");
            } else {
                log("ML bridge not available — running rules-only mode");
            }
        } catch (Exception e) {
            log("ML bridge init failed: " + e.getMessage());
        }
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /**
     * Intercept and enforce Cipher.getInstance()
     */
    public static Cipher getCipher(String transformation, Class<?> caller)
            throws NoSuchAlgorithmException, NoSuchPaddingException {

        long startNs = System.nanoTime();
        long memStart = LatencyProfiler.measureMemory();

        String callerName = caller != null ? caller.getSimpleName() : "Unknown";

        if (SecurityPolicy.isCipherSecure(transformation)) {
            LatencyProfiler.recordLatency(startNs, System.nanoTime(), memStart, LatencyProfiler.measureMemory());
            log("SAFE       [CIPHER] " + transformation + " <- " + callerName);
            return Cipher.getInstance(transformation);
        }

        // Violation detected — start enforcement
        ViolationRecord rec = createRecord(callerName, "getCipher", transformation, ViolationType.CIPHER);
        log("VIOLATION  [CIPHER] " + transformation + " <- " + callerName +
                " (" + rec.getCweId() + ")");

        // ML Behavioral Verification (Layer 2)
        if (mlEnabled) {
            try {
                // Simulate Behavioral Feature Extraction (JVM TI traces would be used here in
                // production)
                String seq = "Cipher.getInstance -> Cipher.init -> Cipher.doFinal";
                double ctEnt = 7.20;
                int ivLen = 0;
                double ivEnt = 0.0;
                double execT = 0.35;
                if (transformation.contains("CBC")) {
                    ivLen = 16;
                    ivEnt = 3.2;
                }

                MLBridge.ClassificationResult result = mlBridge.classifyBehavior(seq, ctEnt, ivLen, ivEnt, execT);
                rec.setMlConfidence(result.confidence);
                log(String.format("  ML Confidence : %.2f  |  Reason: %s", result.confidence, result.explanation));
            } catch (Exception ignored) {
            }
        }

        // Run enforcement loop
        CryptoCorrector corrector = new CryptoCorrector();
        String corrected = corrector.correctCipher(transformation, rec);
        log("  Corrected -> " + corrected);

        // Verify convergence
        ConvergenceVerifier verifier = new ConvergenceVerifier();
        boolean converged = verifier.verifyCipher(corrected, rec);

        if (converged) {
            rec.setStatus(ViolationRecord.Status.VERIFIED);
            log("  CONVERGED in " + rec.getIterations() + " iteration(s)");
        } else {
            rec.setStatus(ViolationRecord.Status.UNRESOLVABLE);
            log("  UNRESOLVABLE after " + SecurityPolicy.MAX_ITERATIONS + " iterations");
        }

        // Generate certificate
        CertificateGenerator.generate(rec);
        eventLog.add(rec);
        CryptoShieldDashboard.push(rec);

        LatencyProfiler.recordLatency(startNs, System.nanoTime(), memStart, LatencyProfiler.measureMemory());

        return Cipher.getInstance(corrected);
    }

    /**
     * Intercept and enforce MessageDigest.getInstance()
     */
    public static MessageDigest getMessageDigest(String algorithm, Class<?> caller)
            throws NoSuchAlgorithmException {

        long startNs = System.nanoTime();
        long memStart = LatencyProfiler.measureMemory();

        String callerName = caller != null ? caller.getSimpleName() : "Unknown";

        if (SecurityPolicy.isHashSecure(algorithm)) {
            LatencyProfiler.recordLatency(startNs, System.nanoTime(), memStart, LatencyProfiler.measureMemory());
            log("SAFE       [HASH]   " + algorithm + " <- " + callerName);
            return MessageDigest.getInstance(algorithm);
        }

        ViolationRecord rec = createRecord(callerName, "getMessageDigest", algorithm, ViolationType.HASH);
        log("VIOLATION  [HASH] " + algorithm + " <- " + callerName +
                " (" + rec.getCweId() + ")");

        if (mlEnabled) {
            try {
                // Simulate Behavioral Feature Extraction
                String seq = "MessageDigest.getInstance -> MessageDigest.update -> MessageDigest.digest";
                MLBridge.ClassificationResult result = mlBridge.classifyBehavior(seq, 7.5, 0, 0.0, 0.15);
                rec.setMlConfidence(result.confidence);
                log(String.format("  ML Confidence : %.2f  |  Reason: %s", result.confidence, result.explanation));
            } catch (Exception ignored) {
            }
        }

        CryptoCorrector corrector = new CryptoCorrector();
        String corrected = corrector.correctHash(algorithm, rec);
        log("  Corrected -> " + corrected);

        ConvergenceVerifier verifier = new ConvergenceVerifier();
        boolean converged = verifier.verifyHash(corrected, rec);

        rec.setStatus(converged ? ViolationRecord.Status.VERIFIED : ViolationRecord.Status.UNRESOLVABLE);
        log("  " + (converged ? "CONVERGED" : "UNRESOLVABLE") +
                " in " + rec.getIterations() + " iteration(s)");

        CertificateGenerator.generate(rec);
        eventLog.add(rec);
        CryptoShieldDashboard.push(rec);

        LatencyProfiler.recordLatency(startNs, System.nanoTime(), memStart, LatencyProfiler.measureMemory());

        return MessageDigest.getInstance(corrected);
    }

    /**
     * Intercept and enforce SecureRandom — warn if explicitly seeded with constant
     */
    public static SecureRandom getSecureRandom() {
        SecureRandom sr = new SecureRandom();
        // No explicit seed = safe
        log("SAFE       [RANDOM] SecureRandom() - system entropy");
        return sr;
    }

    public static SecureRandom getSecureRandomWithSeed(byte[] seed, Class<?> caller) {
        String callerName = caller != null ? caller.getSimpleName() : "Unknown";
        log("VIOLATION  [RANDOM] Hard-coded seed detected <- " + callerName + " (CWE-338)");

        ViolationRecord rec = createRecord(callerName, "getSecureRandom", "HARDCODED_SEED",
                ViolationType.SECURE_RANDOM);
        CertificateGenerator.generate(rec);
        eventLog.add(rec);
        CryptoShieldDashboard.push(rec);

        // Return safely — do NOT use the provided seed
        return new SecureRandom();
    }

    /**
     * Enforce IvParameterSpec — check IV entropy
     */
    public static IvParameterSpec getIvParameterSpec(byte[] iv, Class<?> caller) {
        String callerName = caller != null ? caller.getSimpleName() : "Unknown";
        double entropy = EntropyCalculator.shannonEntropy(iv);

        if (entropy >= SecurityPolicy.MIN_IV_ENTROPY) {
            log("SAFE       [IV]    entropy=" + String.format("%.2f", entropy) + " <- " + callerName);
            return new IvParameterSpec(iv);
        }

        log("VIOLATION  [IV]  entropy=" + String.format("%.2f", entropy) +
                " (< " + SecurityPolicy.MIN_IV_ENTROPY + ") <- " + callerName + " (CWE-329)");

        ViolationRecord rec = createRecord(callerName, "getIvParameterSpec", "CONSTANT_IV", ViolationType.IV_ENTROPY);
        rec.setEntropyBefore(entropy);

        // Replace with securely random IV
        byte[] safeIv = new byte[16];
        new SecureRandom().nextBytes(safeIv);
        rec.setEntropyAfter(EntropyCalculator.shannonEntropy(safeIv));
        rec.setStatus(ViolationRecord.Status.VERIFIED);

        CertificateGenerator.generate(rec);
        eventLog.add(rec);
        CryptoShieldDashboard.push(rec);

        return new IvParameterSpec(safeIv);
    }

    /**
     * Enforce KeyPairGenerator — check RSA Key SIze
     */
    public static KeyPairGenerator getKeyPairGenerator(String algorithm, int keySize, Class<?> caller)
            throws NoSuchAlgorithmException {
        long startNs = System.nanoTime();
        long memStart = LatencyProfiler.measureMemory();
        String callerName = caller != null ? caller.getSimpleName() : "Unknown";

        if ("RSA".equalsIgnoreCase(algorithm)) {
            if (keySize >= SecurityPolicy.MIN_RSA_KEY_BITS) {
                LatencyProfiler.recordLatency(startNs, System.nanoTime(), memStart, LatencyProfiler.measureMemory());
                log("SAFE       [KEY]    " + algorithm + " (" + keySize + " bits) <- " + callerName);
                KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm);
                kpg.initialize(keySize);
                return kpg;
            } else {
                log("VIOLATION  [KEY]  " + algorithm + " " + keySize + " bits (< " + SecurityPolicy.MIN_RSA_KEY_BITS
                        + ") <- " + callerName + " (CWE-326)");

                ViolationRecord rec = createRecord(callerName, "getKeyPairGenerator", "SMALL_KEY",
                        ViolationType.KEY_SIZE);
                rec.setStatus(ViolationRecord.Status.VERIFIED);
                rec.addTrace("Original Key Size: " + keySize + " bits");
                rec.addTrace("Corrected to : " + SecurityPolicy.MIN_RSA_KEY_BITS + " bits");

                CertificateGenerator.generate(rec);
                eventLog.add(rec);
                CryptoShieldDashboard.push(rec);

                LatencyProfiler.recordLatency(startNs, System.nanoTime(), memStart, LatencyProfiler.measureMemory());

                KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm);
                kpg.initialize(SecurityPolicy.MIN_RSA_KEY_BITS);
                return kpg;
            }
        }

        // Default fallback
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm);
        kpg.initialize(keySize);
        return kpg;
    }

    // ── Accessors ─────────────────────────────────────────────────────────────

    public static List<ViolationRecord> getEventLog() {
        return Collections.unmodifiableList(eventLog);
    }

    public static void clearLog() {
        eventLog.clear();
    }

    // ── Internals ─────────────────────────────────────────────────────────────

    private static ViolationRecord createRecord(String caller, String method,
            String algorithm, ViolationType type) {
        String id = "CS-" + System.currentTimeMillis() % 10000 + "-" + idCounter.getAndIncrement();
        ViolationRecord rec = new ViolationRecord(id, caller, method, algorithm, type);
        rec.setCweId(SecurityPolicy.getCwe(algorithm));
        rec.addTrace("Intercepted at: " + caller + "." + method + "()");
        return rec;
    }

    private static void log(String msg) {
        System.out.println("[CryptoShield] " + msg);
    }
}
