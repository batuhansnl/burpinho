package com.sn1persecurity.silentchain.bapp.modules.jwt;

import org.json.JSONObject;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Pure-Java JWT Token parser, decoder, encoder, and rebuilder.
 * Supports JWS (signed) tokens — Header.Payload.Signature format.
 */
public class JwtToken {

    private static final Pattern JWT_PATTERN =
            Pattern.compile("(eyJ[A-Za-z0-9_-]+)\\.(eyJ[A-Za-z0-9_-]+)\\.([A-Za-z0-9_-]*)");

    private static final Pattern BEARER_PATTERN =
            Pattern.compile("Bearer\\s+(eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]*)", Pattern.CASE_INSENSITIVE);

    private final String originalToken;
    private JSONObject header;
    private JSONObject payload;
    private byte[] signatureBytes;
    private String headerB64;
    private String payloadB64;
    private String signatureB64;

    // ---- Construction ----

    private JwtToken(String token) {
        this.originalToken = token;
    }

    /**
     * Parse a raw JWT token string (header.payload.signature).
     */
    public static JwtToken parse(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) {
            throw new IllegalArgumentException("Token is null or blank");
        }

        String token = rawToken.trim();
        // Strip "Bearer " prefix if present
        if (token.toLowerCase().startsWith("bearer ")) {
            token = token.substring(7).trim();
        }

        String[] parts = token.split("\\.");
        if (parts.length < 2 || parts.length > 3) {
            throw new IllegalArgumentException("Invalid JWT format: expected 2-3 dot-separated parts, got " + parts.length);
        }

        JwtToken jwt = new JwtToken(token);
        jwt.headerB64 = parts[0];
        jwt.payloadB64 = parts[1];
        jwt.signatureB64 = parts.length == 3 ? parts[2] : "";

        try {
            jwt.header = new JSONObject(decodeBase64Url(parts[0]));
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to parse JWT header: " + e.getMessage());
        }

        try {
            jwt.payload = new JSONObject(decodeBase64Url(parts[1]));
        } catch (Exception e) {
            throw new IllegalArgumentException("Failed to parse JWT payload: " + e.getMessage());
        }

        jwt.signatureBytes = parts.length == 3 && !parts[2].isEmpty()
                ? Base64.getUrlDecoder().decode(parts[2])
                : new byte[0];

        return jwt;
    }

    /**
     * Extract a JWT from an HTTP request string (searches for Bearer header or eyJ... pattern).
     */
    public static String extractFromRequest(String httpRequest) {
        if (httpRequest == null) return null;

        // Try Authorization: Bearer header first
        Matcher bearerMatcher = BEARER_PATTERN.matcher(httpRequest);
        if (bearerMatcher.find()) {
            return bearerMatcher.group(1);
        }

        // Fall back to generic JWT pattern match
        Matcher jwtMatcher = JWT_PATTERN.matcher(httpRequest);
        if (jwtMatcher.find()) {
            return jwtMatcher.group(0);
        }

        return null;
    }

    /**
     * Check if a string looks like a JWT token.
     */
    public static boolean isJwt(String candidate) {
        if (candidate == null) return false;
        String s = candidate.trim();
        if (s.toLowerCase().startsWith("bearer ")) s = s.substring(7).trim();
        return JWT_PATTERN.matcher(s).matches();
    }

    // ---- Getters ----

    public String originalToken()       { return originalToken; }
    public JSONObject header()          { return header; }
    public JSONObject payload()         { return payload; }
    public byte[] signatureBytes()      { return signatureBytes; }

    public String algorithm()           { return header.optString("alg", "unknown"); }
    public String type()                { return header.optString("typ", "JWT"); }
    public String kid()                 { return header.optString("kid", null); }
    public String jku()                 { return header.optString("jku", null); }
    public String x5u()                 { return header.optString("x5u", null); }

    public String subject()             { return payload.optString("sub", null); }
    public String issuer()              { return payload.optString("iss", null); }
    public String audience()            { return payload.optString("aud", null); }
    public long expiration()            { return payload.optLong("exp", 0); }
    public long issuedAt()              { return payload.optLong("iat", 0); }
    public long notBefore()             { return payload.optLong("nbf", 0); }
    public String jwtId()               { return payload.optString("jti", null); }

    public boolean isExpired() {
        long exp = expiration();
        return exp > 0 && (System.currentTimeMillis() / 1000L) > exp;
    }

    public String headerJson() {
        return header.toString(2);
    }

    public String payloadJson() {
        return payload.toString(2);
    }

    // ---- Token Building ----

    /**
     * Build a new JWT string from the current header and payload (unsigned — empty signature).
     */
    public String buildUnsigned() {
        String h = encodeBase64Url(header.toString());
        String p = encodeBase64Url(payload.toString());
        return h + "." + p + ".";
    }

    /**
     * Build a new JWT string signed with the given HMAC secret.
     */
    public String buildSignedHmac(String secret, String algorithm) {
        String h = encodeBase64Url(header.toString());
        String p = encodeBase64Url(payload.toString());
        String data = h + "." + p;

        String macAlg = hmacAlgorithm(algorithm);
        try {
            Mac mac = Mac.getInstance(macAlg);
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), macAlg));
            byte[] sig = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
            String sigB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(sig);
            return data + "." + sigB64;
        } catch (Exception e) {
            throw new RuntimeException("HMAC signing failed: " + e.getMessage(), e);
        }
    }

    /**
     * Build a token with an arbitrary raw signature.
     */
    public String buildWithSignature(String signatureBase64Url) {
        String h = encodeBase64Url(header.toString());
        String p = encodeBase64Url(payload.toString());
        return h + "." + p + "." + (signatureBase64Url != null ? signatureBase64Url : "");
    }

    // ---- Mutation helpers (return new JwtToken copies) ----

    /**
     * Create a copy with a modified header field.
     */
    public JwtToken withHeaderClaim(String key, Object value) {
        JwtToken copy = cloneToken();
        if (value == null) {
            copy.header.remove(key);
        } else {
            copy.header.put(key, value);
        }
        return copy;
    }

    /**
     * Create a copy with a modified payload field.
     */
    public JwtToken withPayloadClaim(String key, Object value) {
        JwtToken copy = cloneToken();
        if (value == null) {
            copy.payload.remove(key);
        } else {
            copy.payload.put(key, value);
        }
        return copy;
    }

    /**
     * Create a copy with the algorithm changed.
     */
    public JwtToken withAlgorithm(String newAlg) {
        return withHeaderClaim("alg", newAlg);
    }

    /**
     * Create a copy with all header fields replaced.
     */
    public JwtToken withHeader(JSONObject newHeader) {
        JwtToken copy = cloneToken();
        copy.header = new JSONObject(newHeader.toString());
        return copy;
    }

    /**
     * Create a copy with all payload fields replaced.
     */
    public JwtToken withPayload(JSONObject newPayload) {
        JwtToken copy = cloneToken();
        copy.payload = new JSONObject(newPayload.toString());
        return copy;
    }

    // ---- Signature Verification ----

    /**
     * Verify the token's HMAC signature against a candidate secret.
     */
    public boolean verifyHmac(String secret) {
        String alg = algorithm();
        if (!alg.startsWith("HS")) return false;

        String macAlg = hmacAlgorithm(alg);
        try {
            String data = headerB64 + "." + payloadB64;
            Mac mac = Mac.getInstance(macAlg);
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), macAlg));
            byte[] expected = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
            return constantTimeEquals(expected, signatureBytes);
        } catch (Exception e) {
            return false;
        }
    }

    // ---- Static Helpers ----

    public static String decodeBase64Url(String base64Url) {
        byte[] decoded = Base64.getUrlDecoder().decode(padBase64(base64Url));
        return new String(decoded, StandardCharsets.UTF_8);
    }

    public static String encodeBase64Url(String plainText) {
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(plainText.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Returns a human-readable summary of the token.
     */
    public Map<String, String> summary() {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("Algorithm", algorithm());
        m.put("Type", type());
        if (kid() != null) m.put("kid", kid());
        if (jku() != null) m.put("jku", jku());
        if (x5u() != null) m.put("x5u", x5u());
        if (subject() != null) m.put("Subject", subject());
        if (issuer() != null) m.put("Issuer", issuer());
        if (audience() != null) m.put("Audience", audience());
        if (expiration() > 0) {
            m.put("Expires", new java.util.Date(expiration() * 1000L).toString());
            m.put("Expired?", isExpired() ? "YES ⚠️" : "No");
        }
        m.put("Signature Length", signatureBytes.length + " bytes");
        return m;
    }

    @Override
    public String toString() {
        return headerB64 + "." + payloadB64 + "." + signatureB64;
    }

    // ---- Internal ----

    private JwtToken cloneToken() {
        JwtToken copy = new JwtToken(originalToken);
        copy.header = new JSONObject(header.toString());
        copy.payload = new JSONObject(payload.toString());
        copy.signatureBytes = signatureBytes.clone();
        copy.headerB64 = headerB64;
        copy.payloadB64 = payloadB64;
        copy.signatureB64 = signatureB64;
        return copy;
    }

    private static String padBase64(String input) {
        int pad = 4 - (input.length() % 4);
        if (pad == 4) return input;
        return input + "=".repeat(pad);
    }

    private static String hmacAlgorithm(String jwtAlg) {
        return switch (jwtAlg.toUpperCase()) {
            case "HS384" -> "HmacSHA384";
            case "HS512" -> "HmacSHA512";
            default -> "HmacSHA256";
        };
    }

    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a.length != b.length) return false;
        int result = 0;
        for (int i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }
}
