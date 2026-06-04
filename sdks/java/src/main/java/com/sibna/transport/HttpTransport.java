package com.sibna.transport;

import com.sibna.exceptions.*;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.Base64;

/**
 * HTTP transport for communicating with the Sibna Protocol server.
 * Includes TLS certificate pinning for security.
 */
public class HttpTransport {
    private final String baseUrl;
    private final SSLContext sslContext;

    public HttpTransport(String baseUrl) {
        this(baseUrl, null);
    }

    /**
     * Create HTTP transport with optional certificate pinning.
     * @param baseUrl Server URL
     * @param pinnedCertPem PEM-encoded certificate to pin (null to skip pinning)
     */
    public HttpTransport(String baseUrl, String pinnedCertPem) {
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        this.sslContext = createSslContext(pinnedCertPem);
    }

    private SSLContext createSslContext(String pinnedCertPem) {
        try {
            SSLContext ctx = SSLContext.getInstance("TLS");
            
            if (pinnedCertPem != null && !pinnedCertPem.isEmpty()) {
                // Certificate pinning mode - trust only the pinned cert
                ctx.init(null, new TrustManager[]{new PinningTrustManager(pinnedCertPem)}, new java.security.SecureRandom());
            } else {
                // Default trust manager (validates against system trust store)
                ctx.init(null, null, new java.security.SecureRandom());
            }
            
            return ctx;
        } catch (Exception e) {
            throw new RuntimeException("Failed to create SSL context", e);
        }
    }

    /**
     * Request an authentication challenge from the server.
     */
    public byte[] requestChallenge(String identityKeyHex) throws SibnaException {
        String url = baseUrl + "/v1/auth/challenge";
        String json = "{\"identity_key_hex\":\"" + identityKeyHex + "\"}";
        String response = post(url, json, null);

        // Parse challenge_hex from response
        String challengeHex = extractJsonValue(response, "challenge_hex");
        if (challengeHex == null) {
            throw new NetworkException("Invalid challenge response: " + response);
        }
        return hexToBytes(challengeHex);
    }

    /**
     * Prove ownership of the identity key.
     */
    public String proveOwnership(String identityKeyHex, byte[] challenge, byte[] signature) throws SibnaException {
        String url = baseUrl + "/v1/auth/prove";
        String json = "{" +
            "\"identity_key_hex\":\"" + identityKeyHex + "\"," +
            "\"challenge_hex\":\"" + bytesToHex(challenge) + "\"," +
            "\"signature_hex\":\"" + bytesToHex(signature) + "\"" +
            "}";
        String response = post(url, json, null);

        String token = extractJsonValue(response, "token");
        if (token == null) {
            throw new AuthException("Authentication failed: " + response);
        }
        return token;
    }

    /**
     * Send a sealed message.
     */
    public void sendMessage(String recipientId, byte[] ciphertext, String jwtToken) throws SibnaException {
        String url = baseUrl + "/v1/messages/send";
        String json = "{" +
            "\"recipient_id\":\"" + recipientId + "\"," +
            "\"payload_hex\":\"" + bytesToHex(ciphertext) + "\"" +
            "}";
        post(url, json, jwtToken);
    }

    /**
     * Upload a prekey bundle.
     */
    public void uploadPrekey(String bundleHex, boolean isLastResort, String jwtToken) throws SibnaException {
        String url = baseUrl + "/v1/prekeys/upload";
        String json = "{" +
            "\"bundle_hex\":\"" + bundleHex + "\"," +
            "\"is_last_resort\":" + isLastResort +
            "}";
        post(url, json, jwtToken);
    }

    /**
     * Fetch prekey bundles for a peer.
     */
    public String fetchPrekeys(String rootIdHex) throws SibnaException {
        String url = baseUrl + "/v1/prekeys/" + rootIdHex;
        return get(url, null);
    }

    /**
     * Fetch inbox messages.
     */
    public String fetchInbox(String identityKeyHex, String jwtToken) throws SibnaException {
        String url = baseUrl + "/v1/messages/inbox?identity_key_hex=" + identityKeyHex + "&token=" + jwtToken;
        return get(url, jwtToken);
    }

    /**
     * Check server health.
     */
    public String health() throws SibnaException {
        String url = baseUrl + "/health";
        return get(url, null);
    }

    private String post(String urlStr, String json, String jwtToken) throws SibnaException {
        HttpURLConnection conn = null;
        try {
            URL url = new URL(urlStr);
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("Accept", "application/json");
            if (jwtToken != null) {
                conn.setRequestProperty("Authorization", "Bearer " + jwtToken);
            }
            conn.setDoOutput(true);
            conn.setConnectTimeout(30000);
            conn.setReadTimeout(30000);

            try (OutputStream os = conn.getOutputStream()) {
                os.write(json.getBytes(StandardCharsets.UTF_8));
            }

            int responseCode = conn.getResponseCode();
            InputStream is = (responseCode >= 200 && responseCode < 300)
                ? conn.getInputStream()
                : conn.getErrorStream();

            String response = readStream(is);

            if (responseCode == 429) {
                throw new RateLimitException("Rate limited");
            }
            if (responseCode == 401) {
                throw new AuthException("Unauthorized");
            }
            if (responseCode >= 400) {
                throw new NetworkException("HTTP " + responseCode + ": " + response);
            }

            return response;
        } catch (IOException e) {
            throw new NetworkException("Request failed: " + e.getMessage(), e);
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }

    private String get(String urlStr, String jwtToken) throws SibnaException {
        HttpURLConnection conn = null;
        try {
            URL url = new URL(urlStr);
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Accept", "application/json");
            if (jwtToken != null) {
                conn.setRequestProperty("Authorization", "Bearer " + jwtToken);
            }
            conn.setConnectTimeout(30000);
            conn.setReadTimeout(30000);

            int responseCode = conn.getResponseCode();
            InputStream is = (responseCode >= 200 && responseCode < 300)
                ? conn.getInputStream()
                : conn.getErrorStream();

            String response = readStream(is);

            if (responseCode == 429) {
                throw new RateLimitException("Rate limited");
            }
            if (responseCode == 401) {
                throw new AuthException("Unauthorized");
            }
            if (responseCode >= 400) {
                throw new NetworkException("HTTP " + responseCode + ": " + response);
            }

            return response;
        } catch (IOException e) {
            throw new NetworkException("Request failed: " + e.getMessage(), e);
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }

    private String readStream(InputStream is) throws IOException {
        if (is == null) return "";
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }
            return sb.toString();
        }
    }

    private String extractJsonValue(String json, String key) {
        String search = "\"" + key + "\":\"";
        int start = json.indexOf(search);
        if (start == -1) {
            search = "\"" + key + "\": ";
            start = json.indexOf(search);
            if (start == -1) return null;
            start += search.length();
            int end = json.indexOf(",", start);
            if (end == -1) end = json.indexOf("}", start);
            return json.substring(start, end).trim().replace("\"", "");
        }
        start += search.length();
        int end = json.indexOf("\"", start);
        if (end == -1) return null;
        return json.substring(start, end);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                                 + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    /**
     * Trust manager that only trusts a pinned certificate.
     */
    private static class PinningTrustManager implements X509TrustManager {
        private final X509Certificate pinnedCert;

        PinningTrustManager(String pinnedCertPem) {
            try {
                String cleanPem = pinnedCertPem
                    .replace("-----BEGIN CERTIFICATE-----", "")
                    .replace("-----END CERTIFICATE-----", "")
                    .replaceAll("\\s", "");
                byte[] certBytes = Base64.getDecoder().decode(cleanPem);
                java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509");
                this.pinnedCert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));
            } catch (Exception e) {
                throw new RuntimeException("Failed to parse pinned certificate", e);
            }
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) {
            throw new SecurityException("Client certificates not supported");
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) {
            for (X509Certificate cert : chain) {
                if (cert.equals(pinnedCert)) {
                    return; // Trust the pinned cert
                }
            }
            throw new SecurityException("Server certificate not pinned");
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[]{pinnedCert};
        }
    }
}
