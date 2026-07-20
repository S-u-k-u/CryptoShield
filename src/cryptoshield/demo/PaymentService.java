package cryptoshield.demo;

import cryptoshield.agent.CryptoInterceptor;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.util.Base64;

/**
 * CryptoShield Demo — PaymentService (Intentionally Vulnerable)
 *
 * This class deliberately uses INSECURE crypto APIs to demonstrate
 * CryptoShield's interception and enforcement.
 *
 * WITHOUT CryptoShield: all insecure calls succeed silently.
 * WITH CryptoShield: every call is intercepted, corrected, and certified.
 */
public class PaymentService {

    /**
     * VULNERABLE: Uses DES (56-bit, broken since 1998)
     * CWE-327: Use of a Broken or Risky Cryptographic Algorithm
     */
    public byte[] encryptPaymentData(byte[] data, SecretKey key) throws Exception {
        System.out.println("\n─────────────────────────────────────────────────────");
        System.out.println("SCENARIO 1: Encrypting payment data with DES");

        // Show what happens WITHOUT CryptoShield
        Cipher rawDes = Cipher.getInstance("DES");
        KeyGenerator desKg = KeyGenerator.getInstance("DES");
        SecretKey badKey = desKg.generateKey();
        rawDes.init(Cipher.ENCRYPT_MODE, badKey);
        byte[] badCiphertext = rawDes.doFinal(data);
        System.out.println("[Raw Java]  Insecure DES Output : " + Base64.getEncoder().encodeToString(badCiphertext));

        // ❌ VULNERABLE CALL — replaced by CryptoInterceptor
        Cipher cipher = CryptoInterceptor.getCipher("DES", PaymentService.class);

        // The interceptor returns a secure Cipher (AES/GCM) instead of DES
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        SecretKey safeKey = kg.generateKey();

        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        cipher.init(Cipher.ENCRYPT_MODE, safeKey, new GCMParameterSpec(128, iv));

        byte[] safeCiphertext = cipher.doFinal(data);
        System.out.println("[Protected] Secure AES Output   : " + Base64.getEncoder().encodeToString(safeCiphertext));

        return safeCiphertext;
    }

    /**
     * VULNERABLE: Uses MD5 for password hashing
     * CWE-328: Use of Weak Hash
     */
    public byte[] hashPassword(String password) throws Exception {
        System.out.println("\n─────────────────────────────────────────────────────");
        System.out.println("SCENARIO 2: Hashing password with MD5");

        // Show what happens WITHOUT CryptoShield
        MessageDigest rawMd5 = MessageDigest.getInstance("MD5");
        byte[] badHash = rawMd5.digest(password.getBytes());
        System.out.println("[Raw Java]  Insecure MD5 Hash   : " + Base64.getEncoder().encodeToString(badHash));

        // ❌ VULNERABLE CALL — replaced by CryptoInterceptor
        MessageDigest md = CryptoInterceptor.getMessageDigest("MD5", PaymentService.class);

        // Interceptor returns SHA-256 MessageDigest instead
        byte[] safeHash = md.digest(password.getBytes());
        System.out.println("[Protected] Secure SHA-256 Hash : " + Base64.getEncoder().encodeToString(safeHash));
        return safeHash;
    }

    /**
     * VULNERABLE: Uses SHA-1
     * CWE-328: Use of Weak Hash
     */
    public byte[] hashTransactionId(String txId) throws Exception {
        System.out.println("\n─────────────────────────────────────────────────────");
        System.out.println("SCENARIO 3: Hashing transaction ID with SHA-1");

        // Show what happens WITHOUT CryptoShield
        MessageDigest rawSha = MessageDigest.getInstance("SHA-1");
        byte[] badHash = rawSha.digest(txId.getBytes());
        System.out.println("[Raw Java]  Insecure SHA-1 Hash : " + Base64.getEncoder().encodeToString(badHash));

        // ❌ VULNERABLE CALL — replaced by CryptoInterceptor
        MessageDigest md = CryptoInterceptor.getMessageDigest("SHA-1", PaymentService.class);
        byte[] safeHash = md.digest(txId.getBytes());
        System.out.println("[Protected] Secure SHA-256 Hash : " + Base64.getEncoder().encodeToString(safeHash));
        return safeHash;
    }

    /**
     * VULNERABLE: ECB mode — leaks data patterns
     * CWE-327: ECB mode is semantically insecure
     */
    public byte[] encryptWithEcb(byte[] data, SecretKey key) throws Exception {
        System.out.println("\n─────────────────────────────────────────────────────");
        System.out.println("SCENARIO 4: Encrypting with AES/ECB (penguin test failure)");

        // Show what happens WITHOUT CryptoShield
        Cipher rawEcb = Cipher.getInstance("AES/ECB/PKCS5Padding");
        KeyGenerator ecbKg = KeyGenerator.getInstance("AES");
        ecbKg.init(256);
        SecretKey badKey = ecbKg.generateKey();
        rawEcb.init(Cipher.ENCRYPT_MODE, badKey);
        byte[] badCiphertext = rawEcb.doFinal(data);
        System.out.println("[Raw Java]  Insecure AES/ECB Out: " + Base64.getEncoder().encodeToString(badCiphertext));

        // ❌ VULNERABLE CALL — replaced by CryptoInterceptor
        Cipher cipher = CryptoInterceptor.getCipher("AES/ECB/PKCS5Padding", PaymentService.class);

        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        SecretKey safeKey = kg.generateKey();

        // After correction this will be GCM — need IV
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        try {
            cipher.init(Cipher.ENCRYPT_MODE, safeKey, new GCMParameterSpec(128, iv));
        } catch (Exception e) {
            cipher.init(Cipher.ENCRYPT_MODE, safeKey);
        }

        byte[] safeCiphertext = cipher.doFinal(data);
        System.out.println("[Protected] Secure AES/GCM Out  : " + Base64.getEncoder().encodeToString(safeCiphertext));
        return safeCiphertext;
    }

    /**
     * VULNERABLE: Hard-coded constant IV
     * CWE-329: Not Using an Unpredictable IV with CBC Mode
     */
    public byte[] encryptWithConstantIv(byte[] data, SecretKey key) throws Exception {
        System.out.println("\n─────────────────────────────────────────────────────");
        System.out.println("SCENARIO 5: Using constant IV 'Hello World!!!!!'");

        // Show what happens WITHOUT CryptoShield
        byte[] constantIv = "Hello World!!!!!".getBytes(); // entropy ≈ 3.2 bits/byte
        Cipher rawCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        KeyGenerator rawKg = KeyGenerator.getInstance("AES");
        rawKg.init(256);
        SecretKey badKey = rawKg.generateKey();
        rawCipher.init(Cipher.ENCRYPT_MODE, badKey, new IvParameterSpec(constantIv));
        byte[] badCiphertext = rawCipher.doFinal(data);
        System.out.println("[Raw Java]  Constant IV Output  : " + Base64.getEncoder().encodeToString(badCiphertext));

        // ❌ VULNERABLE CALL — replaced by CryptoInterceptor
        IvParameterSpec ivSpec = CryptoInterceptor.getIvParameterSpec(constantIv, PaymentService.class);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        cipher.init(Cipher.ENCRYPT_MODE, kg.generateKey(), ivSpec);

        byte[] safeCiphertext = cipher.doFinal(data);
        System.out.println("[Protected] Randomized IV Output: " + Base64.getEncoder().encodeToString(safeCiphertext));

        return safeCiphertext;
    }

    /**
     * VULNERABLE: Uses explicitly hardcoded SecureRandom seed
     * CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)
     */
    public byte[] encryptWithHardcodedSeed(byte[] data, SecretKey key) throws Exception {
        System.out.println("\n─────────────────────────────────────────────────────");
        System.out.println("SCENARIO 7: Using hardcoded SecureRandom seed");

        byte[] badSeed = "static_seed".getBytes();

        // Show what happens WITHOUT CryptoShield
        SecureRandom rawRandom = new SecureRandom(badSeed);
        byte[] rawOutput = new byte[16];
        rawRandom.nextBytes(rawOutput);
        System.out.println("[Raw Java]  Predictable PRNG Out: " + Base64.getEncoder().encodeToString(rawOutput));

        // ❌ VULNERABLE CALL — replaced by CryptoInterceptor
        SecureRandom random = CryptoInterceptor.getSecureRandomWithSeed(badSeed, PaymentService.class);
        byte[] safeOutput = new byte[16];
        random.nextBytes(safeOutput);
        System.out.println("[Protected] Secure Random Output: " + Base64.getEncoder().encodeToString(safeOutput));

        return safeOutput;
    }

    /**
     * VULNERABLE: Uses weak RSA key size (512 bits)
     * CWE-326: Inadequate Encryption Strength
     */
    public KeyPair generateWeakRSAKey() throws Exception {
        System.out.println("\n─────────────────────────────────────────────────────");
        System.out.println("SCENARIO 8: Generating Weak RSA Key Pair (512 bits)");

        // Show what happens WITHOUT CryptoShield
        KeyPairGenerator rawKpg = KeyPairGenerator.getInstance("RSA");
        rawKpg.initialize(512);
        rawKpg.generateKeyPair();
        System.out.println("[Raw Java]  Insecure RSA Key Size: 512 bits requested");

        // ❌ VULNERABLE CALL — replaced by CryptoInterceptor
        KeyPairGenerator kpg = CryptoInterceptor.getKeyPairGenerator("RSA", 512, PaymentService.class);
        KeyPair safePair = kpg.generateKeyPair();
        System.out.println("[Protected] Secure RSA Key Size  : 2048 bits physically generated");

        return safePair;
    }

    /**
     * SAFE: Already using AES/GCM — should pass straight through
     */
    public byte[] encryptSafely(byte[] data) throws Exception {
        System.out.println("\n─────────────────────────────────────────────────────");
        System.out.println("SCENARIO 6: Safe call — AES/GCM/NoPadding (should pass through)");

        // ✓ SAFE CALL — interceptor logs it and passes through
        Cipher cipher = CryptoInterceptor.getCipher("AES/GCM/NoPadding", PaymentService.class);

        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        SecretKey key = kg.generateKey();
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        byte[] safeCiphertext = cipher.doFinal(data);
        System.out.println("[Protected] Secure AES/GCM Out  : " + Base64.getEncoder().encodeToString(safeCiphertext));
        return safeCiphertext;
    }
}
