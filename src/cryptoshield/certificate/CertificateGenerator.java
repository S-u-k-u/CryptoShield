package cryptoshield.certificate;

import cryptoshield.policy.ViolationRecord;

import java.io.*;
import java.nio.file.*;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * CryptoShield Security Assurance Certificate Generator (Component 4)
 *
 * Generates a JSON audit certificate for every enforcement action.
 * Certificates are written to ./certificates/ and to an HTML summary.
 */
public class CertificateGenerator {

    private static final String CERT_DIR = "certificates";
    private static final List<ViolationRecord> allRecords = new ArrayList<>();

    public static void generate(ViolationRecord rec) {
        allRecords.add(rec);
        try {
            Files.createDirectories(Paths.get(CERT_DIR));
            String json = buildJson(rec);

            // Write individual certificate
            String filename = CERT_DIR + "/" + rec.getId() + ".json";
            Files.writeString(Paths.get(filename), json);

            // Update cumulative HTML report
            updateHtmlReport();

            System.out.println("[CryptoShield] [CERT] Certificate issued: " + filename);
        } catch (IOException e) {
            System.err.println("[CryptoShield] Certificate write failed: " + e.getMessage());
        }
    }

    private static String buildJson(ViolationRecord rec) {
        DateTimeFormatter fmt = DateTimeFormatter.ISO_INSTANT;
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"session_id\":           \"").append(rec.getId()).append("\",\n");
        sb.append("  \"timestamp\":            \"").append(fmt.format(rec.getTimestamp())).append("\",\n");
        sb.append("  \"caller_class\":         \"").append(rec.getCallerClass()).append("\",\n");
        sb.append("  \"violation_type\":       \"").append(rec.getType()).append("\",\n");
        sb.append("  \"original_algorithm\":   \"").append(rec.getOriginalAlgorithm()).append("\",\n");
        sb.append("  \"cwe_violated\":         \"").append(rec.getCweId()).append("\",\n");
        if (rec.getMlConfidence() >= 0) {
            sb.append("  \"ml_confidence\":        ").append(String.format("%.4f", rec.getMlConfidence()))
                    .append(",\n");
        }
        sb.append("  \"corrected_algorithm\":  \"").append(strOrNull(rec.getCorrectedAlgorithm())).append("\",\n");
        sb.append("  \"enforcement_iterations\": ").append(rec.getIterations()).append(",\n");
        if (rec.getEntropyBefore() > 0) {
            sb.append("  \"entropy_before\":       ").append(String.format("%.4f", rec.getEntropyBefore()))
                    .append(",\n");
            sb.append("  \"entropy_after\":        ").append(String.format("%.4f", rec.getEntropyAfter()))
                    .append(",\n");
        }
        sb.append("  \"whitelist_check\":      ").append(rec.isWhitelistCheckPassed()).append(",\n");
        sb.append("  \"ecb_pattern_test\":     ").append(rec.isEcbTestPassed()).append(",\n");
        sb.append("  \"fixed_point_reached\":  ").append(rec.getStatus() == ViolationRecord.Status.VERIFIED)
                .append(",\n");
        sb.append("  \"status\":               \"").append(rec.getStatus()).append("\",\n");
        sb.append("  \"enforcement_trace\": [\n");
        List<String> trace = rec.getTrace();
        for (int i = 0; i < trace.size(); i++) {
            sb.append("    \"").append(trace.get(i).replace("\"", "'")).append("\"");
            if (i < trace.size() - 1)
                sb.append(",");
            sb.append("\n");
        }
        sb.append("  ]\n");
        sb.append("}\n");
        return sb.toString();
    }

    private static void updateHtmlReport() throws IOException {
        StringBuilder html = new StringBuilder();
        html.append("<!DOCTYPE html><html><head><meta charset='utf-8'>\n");
        html.append("<title>CryptoShield — Enforcement Report</title>\n");
        html.append("<style>\n");
        html.append("body{font-family:Segoe UI,sans-serif;background:#0D1B2A;color:#AED6F1;margin:0;padding:20px}\n");
        html.append(
                "h1{color:#D4AC0D;font-size:2em} h2{color:#2E86C1;border-bottom:1px solid #1B4F72;padding-bottom:6px}\n");
        html.append(
                ".card{background:#1B4F72;border-radius:8px;padding:16px;margin:10px 0;border-left:4px solid #2E86C1}\n");
        html.append(".card.violated{border-left-color:#C0392B}\n");
        html.append(".card.verified{border-left-color:#1E8449}\n");
        html.append(".card.unresolvable{border-left-color:#D4AC0D}\n");
        html.append(
                ".badge{display:inline-block;padding:3px 10px;border-radius:12px;font-size:0.8em;font-weight:bold}\n");
        html.append(".badge.VERIFIED{background:#1E8449;color:#fff}\n");
        html.append(".badge.UNRESOLVABLE{background:#D4AC0D;color:#000}\n");
        html.append(".badge.DETECTED{background:#C0392B;color:#fff}\n");
        html.append(".field{margin:4px 0;font-size:0.9em}\n");
        html.append(".label{color:#7F8C8D;display:inline-block;width:200px}\n");
        html.append(".value{color:#ECF0F1}\n");
        html.append(".value.ok{color:#1E8449}\n");
        html.append(".value.bad{color:#C0392B}\n");
        html.append(".stat-row{display:flex;gap:20px;flex-wrap:wrap;margin:20px 0}\n");
        html.append(".stat{background:#1B4F72;border-radius:8px;padding:16px;min-width:120px;text-align:center}\n");
        html.append(".stat .num{font-size:2.5em;font-weight:bold;color:#D4AC0D}\n");
        html.append(".stat .lbl{font-size:0.85em;color:#7F8C8D}\n");
        html.append(
                "pre{background:#0A1628;padding:12px;border-radius:6px;font-size:0.8em;overflow-x:auto;color:#79B8FF}\n");
        html.append("</style></head><body>\n");
        html.append("<h1>🛡 CryptoShield — Live Enforcement Report</h1>\n");

        // Stats
        long total = allRecords.size();
        long verified = allRecords.stream().filter(r -> r.getStatus() == ViolationRecord.Status.VERIFIED).count();
        long unres = allRecords.stream().filter(r -> r.getStatus() == ViolationRecord.Status.UNRESOLVABLE).count();
        long cipher = allRecords.stream().filter(r -> r.getType() == ViolationRecord.ViolationType.CIPHER).count();
        long hash = allRecords.stream().filter(r -> r.getType() == ViolationRecord.ViolationType.HASH).count();

        html.append("<div class='stat-row'>\n");
        html.append(stat(total, "Total Violations"));
        html.append(stat(verified, "Enforced &amp; Verified"));
        html.append(stat(unres, "Unresolvable"));
        html.append(stat(cipher, "Cipher Violations"));
        html.append(stat(hash, "Hash Violations"));
        html.append("</div>\n");

        html.append("<h2>Enforcement Events</h2>\n");

        for (ViolationRecord r : allRecords) {
            String cls = r.getStatus().toString().toLowerCase();
            html.append("<div class='card ").append(cls).append("'>\n");
            html.append("<span class='badge ").append(r.getStatus()).append("'>")
                    .append(r.getStatus()).append("</span>\n");
            html.append("&nbsp;&nbsp;<strong>" + r.getId() + "</strong>\n");
            field(html, "Original Algorithm", r.getOriginalAlgorithm(), "bad");
            field(html, "Corrected To", strOrNull(r.getCorrectedAlgorithm()), "ok");
            field(html, "CWE", r.getCweId(), null);
            field(html, "Caller", r.getCallerClass() + "." + r.getCallerMethod() + "()", null);
            field(html, "Iterations", String.valueOf(r.getIterations()), null);
            if (r.getMlConfidence() >= 0)
                field(html, "ML Confidence", String.format("%.2f%%", r.getMlConfidence() * 100), "ok");
            if (r.getEntropyBefore() > 0) {
                field(html, "IV Entropy Before", String.format("%.4f bits/byte", r.getEntropyBefore()), "bad");
                field(html, "IV Entropy After", String.format("%.4f bits/byte", r.getEntropyAfter()), "ok");
            }
            field(html, "Whitelist Check", r.isWhitelistCheckPassed() ? "PASS ✓" : "FAIL ✗",
                    r.isWhitelistCheckPassed() ? "ok" : "bad");
            field(html, "ECB Pattern Test", r.isEcbTestPassed() ? "PASS ✓" : "FAIL ✗",
                    r.isEcbTestPassed() ? "ok" : "bad");

            html.append(
                    "<details><summary style='cursor:pointer;color:#7F8C8D;margin-top:8px'>Enforcement Trace</summary>\n");
            html.append("<pre>");
            r.getTrace().forEach(t -> html.append(escHtml(t)).append("\n"));
            html.append("</pre></details>\n");
            html.append("</div>\n");
        }

        html.append("<p style='color:#7F8C8D;font-size:0.8em;margin-top:30px'>");
        html.append("Generated by CryptoShield — Sanjay Venkat &amp; Sukumaran Sakthevelan</p>\n");
        html.append("</body></html>\n");

        Files.writeString(Paths.get(CERT_DIR + "/report.html"), html.toString());
    }

    private static String stat(long n, String lbl) {
        return "<div class='stat'><div class='num'>" + n + "</div><div class='lbl'>" + lbl + "</div></div>\n";
    }

    private static void field(StringBuilder sb, String label, String value, String cls) {
        sb.append("<div class='field'><span class='label'>").append(label).append("</span>")
                .append("<span class='value").append(cls != null ? " " + cls : "").append("'>")
                .append(value != null ? escHtml(value) : "—").append("</span></div>\n");
    }

    private static String escHtml(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    private static String strOrNull(String s) {
        return s != null ? s : "—";
    }
}
