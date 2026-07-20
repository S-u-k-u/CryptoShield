package cryptoshield.ml;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;

/**
 * Bridge between the Java enforcement engine and the Python ML classifier.
 * Sends classification requests via HTTP to a local Flask service.
 *
 * If the ML service is not running, all methods return -1.0 (unavailable)
 * and the system falls back to rule-only enforcement.
 */
public class MLBridge {

    public static class ClassificationResult {
        public double confidence;
        public String explanation;

        public ClassificationResult(double c, String e) {
            confidence = c;
            explanation = e;
        }
    }

    private static final String ML_URL = "http://127.0.0.1:5001/classify";
    private static final int TIMEOUT_MS = 500;

    private boolean available = false;

    public MLBridge() {
        // Quick availability check on init
        try {
            URL url = new URL("http://127.0.0.1:5001/health");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(TIMEOUT_MS);
            conn.setReadTimeout(TIMEOUT_MS);
            conn.setRequestMethod("GET");
            available = conn.getResponseCode() == 200;
            conn.disconnect();
        } catch (Exception ignored) {
            available = false;
        }
    }

    public boolean isAvailable() {
        return available;
    }

    /**
     * Research-Grade Behavioral Classification (Layer 2 Verification)
     * 
     * @return ClassificationResult containing confidence score and SHAP explanation
     */
    public ClassificationResult classifyBehavior(String sequence, double ciphertextEntropy, int ivLength,
            double ivEntropy, double execTime) {
        if (!available)
            return new ClassificationResult(-1.0, "ML Service Unavailable");
        try {
            String body = String.format(
                    "{\"sequence\": \"%s\", \"ciphertext_entropy\": %.2f, \"iv_length\": %d, \"iv_entropy\": %.2f, \"exec_time\": %.2f}",
                    sequence, ciphertextEntropy, ivLength, ivEntropy, execTime);
            URL url = new URL("http://127.0.0.1:5001/verify_behavior");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(TIMEOUT_MS);
            conn.setReadTimeout(TIMEOUT_MS);
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setDoOutput(true);
            conn.getOutputStream().write(body.getBytes(StandardCharsets.UTF_8));

            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(conn.getInputStream()));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null)
                sb.append(line);
            reader.close();
            conn.disconnect();

            String response = sb.toString();
            // Parse {"confidence": 0.98, "explanation": "IV_Entropy deviation"}

            // Extract confidence using basic string ops
            int confStart = response.indexOf("\"confidence\":") + 13;
            int confEnd = response.indexOf(",", confStart);
            if (confEnd == -1)
                confEnd = response.indexOf("}", confStart);
            double conf = Double.parseDouble(response.substring(confStart, confEnd).trim());

            // Extract explanation using basic string ops
            String exp = "Deviation detected";
            int expStart = response.indexOf("\"explanation\":");
            if (expStart != -1) {
                expStart += 14;
                int expQuoteStart = response.indexOf("\"", expStart) + 1;
                int expQuoteEnd = response.indexOf("\"", expQuoteStart);
                if (expQuoteStart > 0 && expQuoteEnd > expQuoteStart) {
                    exp = response.substring(expQuoteStart, expQuoteEnd);
                }
            }

            return new ClassificationResult(conf, exp);
        } catch (Exception e) {
            return new ClassificationResult(-1.0, "ML Parsing Error: " + e.getMessage());
        }
    }
}
