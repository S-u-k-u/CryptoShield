package cryptoshield.policy;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Immutable record of a single crypto API violation and its enforcement.
 */
public class ViolationRecord {

    public enum Status { DETECTED, ENFORCED, VERIFIED, UNRESOLVABLE }
    public enum ViolationType { CIPHER, HASH, SECURE_RANDOM, IV_ENTROPY, KEY_SIZE }

    private final String     id;
    private final Instant    timestamp;
    private final String     callerClass;
    private final String     callerMethod;
    private final String     originalAlgorithm;
    private final ViolationType type;
    private       String     correctedAlgorithm;
    private       String     cweId;
    private       Status     status;
    private       int        iterations;
    private       double     entropyBefore;
    private       double     entropyAfter;
    private       boolean    whitelistCheckPassed;
    private       boolean    ecbTestPassed;
    private       double     mlConfidence;
    private final List<String> trace = new ArrayList<>();

    public ViolationRecord(String id, String callerClass, String callerMethod,
                           String originalAlgorithm, ViolationType type) {
        this.id                = id;
        this.timestamp         = Instant.now();
        this.callerClass       = callerClass;
        this.callerMethod      = callerMethod;
        this.originalAlgorithm = originalAlgorithm;
        this.type              = type;
        this.status            = Status.DETECTED;
        this.mlConfidence      = -1.0;
    }

    // ── Setters ────────────────────────────────────────────────────────
    public void setCorrectedAlgorithm(String c) { this.correctedAlgorithm = c; }
    public void setCweId(String c)               { this.cweId = c; }
    public void setStatus(Status s)              { this.status = s; }
    public void setIterations(int i)             { this.iterations = i; }
    public void setEntropyBefore(double e)       { this.entropyBefore = e; }
    public void setEntropyAfter(double e)        { this.entropyAfter = e; }
    public void setWhitelistCheckPassed(boolean b){ this.whitelistCheckPassed = b; }
    public void setEcbTestPassed(boolean b)      { this.ecbTestPassed = b; }
    public void setMlConfidence(double d)        { this.mlConfidence = d; }
    public void addTrace(String line)            { this.trace.add(line); }

    // ── Getters ────────────────────────────────────────────────────────
    public String      getId()                   { return id; }
    public Instant     getTimestamp()            { return timestamp; }
    public String      getCallerClass()          { return callerClass; }
    public String      getCallerMethod()         { return callerMethod; }
    public String      getOriginalAlgorithm()    { return originalAlgorithm; }
    public ViolationType getType()               { return type; }
    public String      getCorrectedAlgorithm()   { return correctedAlgorithm; }
    public String      getCweId()                { return cweId; }
    public Status      getStatus()               { return status; }
    public int         getIterations()           { return iterations; }
    public double      getEntropyBefore()        { return entropyBefore; }
    public double      getEntropyAfter()         { return entropyAfter; }
    public boolean     isWhitelistCheckPassed()  { return whitelistCheckPassed; }
    public boolean     isEcbTestPassed()         { return ecbTestPassed; }
    public double      getMlConfidence()         { return mlConfidence; }
    public List<String> getTrace()               { return trace; }

    @Override
    public String toString() {
        return String.format("[ViolationRecord id=%s type=%s original=%s corrected=%s status=%s iter=%d]",
            id, type, originalAlgorithm, correctedAlgorithm, status, iterations);
    }
}
