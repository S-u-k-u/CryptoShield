package cryptoshield.demo;

import cryptoshield.agent.CryptoInterceptor;
import cryptoshield.agent.LatencyProfiler;
import cryptoshield.policy.ViolationRecord;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.util.List;
import java.util.Scanner;

/**
 * CryptoShield — Main Demo Runner
 *
 * Run this class to see the full enforcement pipeline in action.
 *
 * What you will see:
 * 1. Vulnerable PaymentService makes 5 insecure crypto calls
 * 2. CryptoShield intercepts each call before it completes
 * 3. Fixed-point convergence loop verifies corrections
 * 4. JSON certificates are written to ./certificates/
 * 5. HTML report is generated at ./certificates/report.html
 */
public class CryptoShieldMain {

    public static void main(String[] args) throws Exception {

        printBanner();

        PaymentService service = new PaymentService();

        Scanner scanner = new Scanner(System.in);
        System.out.println("=====================================================================");
        System.out.println("  ENTER CUSTOM DATA TO ENCRYPT: ");
        System.out.print("  > ");
        String userInput = scanner.nextLine();

        if (userInput == null || userInput.trim().isEmpty()) {
            userInput = "Sensitive payment data: Card 4111-1111-1111-1111";
            System.out.println("  (Using default sample data)");
        }
        scanner.close();
        System.out.println("=====================================================================\n");

        byte[] sampleData = userInput.getBytes();

        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        SecretKey dummyKey = kg.generateKey();

        // ── Run all scenarios ─────────────────────────────────────────────
        try {
            service.encryptPaymentData(sampleData, dummyKey);
        } catch (Exception e) {
            System.out.println("  (Note: " + e.getMessage() + ")");
        }

        try {
            service.hashPassword("super_secret_123");
        } catch (Exception e) {
            System.out.println("  (Note: " + e.getMessage() + ")");
        }

        try {
            service.hashTransactionId("TXN-20260227-9841");
        } catch (Exception e) {
            System.out.println("  (Note: " + e.getMessage() + ")");
        }

        try {
            service.encryptWithEcb(sampleData, dummyKey);
        } catch (Exception e) {
            System.out.println("  (Note: " + e.getMessage() + ")");
        }

        try {
            service.encryptWithConstantIv(sampleData, dummyKey);
        } catch (Exception e) {
            System.out.println("  (Note: " + e.getMessage() + ")");
        }

        try {
            service.encryptWithHardcodedSeed(sampleData, dummyKey);
        } catch (Exception e) {
            System.out.println("  (Note: " + e.getMessage() + ")");
        }

        try {
            service.generateWeakRSAKey();
        } catch (Exception e) {
            System.out.println("  (Note: " + e.getMessage() + ")");
        }

        try {
            service.encryptSafely(sampleData);
        } catch (Exception e) {
            System.out.println("  (Note: " + e.getMessage() + ")");
        }

        // ── Summary ───────────────────────────────────────────────────────
        printSummary();
    }

    private static void printBanner() {
        System.out.println();
        System.out.println("╔══════════════════════════════════════════════════════════════════╗");
        System.out.println("║          CryptoShield - Runtime Enforcement Framework            ║");
        System.out.println("║     Sanjay Venkat (23BCE1928) & Sukumaran Sakthevelan (23BCE1876)║");
        System.out.println("║     Based on: Torres et al. (2023) - RVSec                       ║");
        System.out.println("╚══════════════════════════════════════════════════════════════════╝");
        System.out.println();
        System.out.println("Starting CryptoShield enforcement engine...");
        System.out.println("Running 8 scenarios: 7 vulnerable + 1 safe\n");
    }

    private static void printSummary() {
        List<ViolationRecord> log = CryptoInterceptor.getEventLog();

        long violations = log.size();
        long verified = log.stream().filter(r -> r.getStatus() == ViolationRecord.Status.VERIFIED).count();
        long unresolved = log.stream().filter(r -> r.getStatus() == ViolationRecord.Status.UNRESOLVABLE).count();
        double avgIter = log.stream().mapToInt(ViolationRecord::getIterations).average().orElse(0);

        System.out.println();
        System.out.println("══════════════════════════════════════════════════════════════════");
        System.out.println("                   ENFORCEMENT SUMMARY");
        System.out.println("══════════════════════════════════════════════════════════════════");
        System.out.printf("  Total violations intercepted : %d%n", violations);
        System.out.printf("  Enforced & Verified          : %d%n", verified);
        System.out.printf("  Unresolvable                 : %d%n", unresolved);
        System.out.printf("  Avg convergence iterations   : %.1f%n", avgIter);
        System.out.println();
        System.out.println("  Violations by type:");
        for (ViolationRecord r : log) {
            System.out.printf("    [%s] %-20s -> %-25s [%s] [%s]%n",
                    r.getCweId(),
                    r.getOriginalAlgorithm(),
                    strOrDash(r.getCorrectedAlgorithm()),
                    r.getStatus(),
                    r.getType());
        }
        System.out.println();
        System.out.println("  [LOG] Certificates written to: ./certificates/");
        System.out.println("  [WWW] HTML report at: ./certificates/report.html");
        System.out.println("     Open report.html in your browser to see the live dashboard.");
        System.out.println("══════════════════════════════════════════════════════════════════");

        System.out.println();
        LatencyProfiler.printAcademicOverheadMetrics();
    }

    private static String strOrDash(String s) {
        return s != null ? s : "-";
    }
}
