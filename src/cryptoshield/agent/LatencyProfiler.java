package cryptoshield.agent;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Academic-Grade Latency and Memory Profiler for CryptoShield
 * Required for IEEE S&P / USENIX Security benchmarks.
 */
public class LatencyProfiler {

    private static final List<Long> executionLatenciesNs = new CopyOnWriteArrayList<>();
    private static long totalMemoryOverheadBytes = 0;

    // Start tracking memory before an interception
    public static long measureMemory() {
        return Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory();
    }

    // Add a completed latency measurement (in nanoseconds)
    public static void recordLatency(long startNs, long endNs, long startMem, long endMem) {
        executionLatenciesNs.add(endNs - startNs);
        long overhead = endMem - startMem;
        if (overhead > 0) {
            totalMemoryOverheadBytes += overhead;
        }
    }

    /**
     * Calculates the P50, P90, and P99 percentiles for intercepted API calls.
     */
    public static void printAcademicOverheadMetrics() {
        if (executionLatenciesNs.isEmpty())
            return;

        List<Long> sorted = new ArrayList<>(executionLatenciesNs);
        Collections.sort(sorted);

        int size = sorted.size();

        // Convert to milliseconds for standard reporting
        double p50 = sorted.get((int) (size * 0.50)) / 1_000_000.0;
        double p90 = sorted.get((int) (size * 0.90)) / 1_000_000.0;
        double p99 = sorted.get((int) (size * 0.99)) / 1_000_000.0;
        double avg = sorted.stream().mapToLong(Long::longValue).average().orElse(0) / 1_000_000.0;

        System.out.println("╔═══════════════════════════════════════════════════════════╗");
        System.out.println("║            CRYPTOSHIELD ACADEMIC PROFILER REPORT          ║");
        System.out.println("╠═══════════════════════════════════════════════════════════╣");
        System.out.println(String.format("║  Total Interceptions    : %-32s║", size));
        System.out.println(String.format("║  Average Latency        : %-6.2f ms                      ║", avg));
        System.out.println(String.format("║  Median (P50) Latency   : %-6.2f ms                      ║", p50));
        System.out.println(String.format("║  P90 Latency Tail       : %-6.2f ms                      ║", p90));
        System.out.println(String.format("║  P99 Latency Tail       : %-6.2f ms                      ║", p99));
        System.out.println(String.format("║  Total Memory Allocation: %-7.2f KB                      ║",
                totalMemoryOverheadBytes / 1024.0));
        System.out.println("╚═══════════════════════════════════════════════════════════╝");
    }
}
