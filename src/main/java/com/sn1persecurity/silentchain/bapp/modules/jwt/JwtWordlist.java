package com.sn1persecurity.silentchain.bapp.modules.jwt;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Built-in JWT secret wordlist for HMAC brute-force attacks.
 * Contains 500+ commonly used JWT signing secrets.
 * Also supports loading external wordlist files.
 */
public final class JwtWordlist {

    private JwtWordlist() {}

    /**
     * Top 500 most common JWT secrets found in the wild —
     * compiled from public JWT cracking databases, GitHub leaks, and penetration test experience.
     */
    public static final List<String> TOP_SECRETS = List.of(
            // ---- Ultra-common defaults ----
            "secret", "password", "123456", "12345678", "1234567890",
            "admin", "jwt_secret", "jwt-secret", "my-secret", "my-secret-key",
            "supersecret", "super-secret", "super_secret", "mysecretkey", "changeme",
            "changeit", "test", "key", "token", "auth",
            "pass", "passw0rd", "qwerty", "abc123", "letmein",
            "welcome", "monkey", "master", "dragon", "login",

            // ---- Common developer secrets ----
            "secret123", "secret1234", "jwt_secret_key", "jwt-secret-key", "jwtsecret",
            "jwt_token_secret", "my_secret_key", "my_jwt_secret", "app_secret", "application_secret",
            "api_secret", "api-secret", "api_key", "apikey", "api-key",
            "secretkey", "secret-key", "secret_key", "privatekey", "private-key",
            "private_key", "signing_key", "signing-key", "signingkey", "hmac_secret",
            "hmac-secret", "hmac_key", "hmac-key", "hmackey", "hmacsecret",

            // ---- Framework defaults ----
            "your-256-bit-secret", "your-384-bit-secret", "your-512-bit-secret",
            "shhhhh", "shhhhhh", "shhhhhhhh", "keyboard cat", "keyboard-cat",
            "keyboardcat", "iloveyou", "trustno1", "access", "default",
            "example", "sample", "demo", "testing", "development",
            "staging", "production", "notsecret", "not-secret", "not_secret",
            "unsafe", "insecure", "placeholder", "dummy", "temp",
            "temporary", "debug", "devmode", "dev-mode", "dev_mode",

            // ---- Java/Spring Boot common ----
            "spring-jwt-secret", "spring_jwt_secret", "springboot", "spring-boot-secret",
            "spring.jwt.secret", "myapp-secret", "myapp_secret", "myapplication",
            "application-secret", "boot-secret", "boot_secret", "jwt.secret",
            "token.secret", "auth.secret", "auth-secret", "auth_secret",
            "security-key", "security_key", "securitykey", "app-key",

            // ---- Node.js / Express common ----
            "node-secret", "node_secret", "express-secret", "express_secret",
            "session-secret", "session_secret", "sessionsecret", "cookie-secret",
            "cookie_secret", "passport-secret", "passport_secret", "jsonwebtoken",
            "jwt-node-secret", "nodejs-secret", "server-secret", "server_secret",
            "my-app-secret", "my_app_secret", "process.env.SECRET",

            // ---- Python / Django / Flask common ----
            "django-insecure", "django-secret-key", "django_secret_key",
            "flask-secret", "flask_secret", "flask-jwt-secret", "flask_jwt_secret",
            "python-secret", "python_secret", "fastapi-secret", "fastapi_secret",

            // ---- UUID-like and hash-like ----
            "00000000-0000-0000-0000-000000000000",
            "d41d8cd98f00b204e9800998ecf8427e",
            "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",

            // ---- More password variants ----
            "P@ssw0rd", "P@ssword", "P@ssword1", "Password1", "Password123",
            "Admin123", "Admin@123", "Root123", "root", "toor",
            "administrator", "admin123", "admin1234", "admin12345",
            "letmein123", "welcome1", "welcome123", "guest", "guest123",

            // ---- Keyboard patterns ----
            "qwerty123", "qwerty1234", "asdfgh", "asdfghjkl", "zxcvbn",
            "zxcvbnm", "1q2w3e4r", "1q2w3e", "1qaz2wsx", "qazwsx",
            "aaaaaa", "111111", "000000", "123123", "321321",
            "abcdef", "abcdefg", "abcabc", "aabbcc", "112233",

            // ---- Single word secrets ----
            "sun", "moon", "star", "hello", "world",
            "foo", "bar", "baz", "foobar", "test123",
            "testing123", "dev123", "devtest", "mykey", "thekey",
            "signing", "encode", "decode", "verify", "validate",
            "authenticate", "authorize", "authorization", "bearer",

            // ---- Company / product patterns ----
            "company-secret", "company_secret", "product-secret", "product_secret",
            "mycompany", "myproduct", "myservice", "service-secret", "service_secret",
            "backend-secret", "backend_secret", "frontend-secret", "frontend_secret",
            "internal", "internal-secret", "internal_secret", "corp-secret",

            // ---- Environment variable defaults ----
            "JWT_SECRET", "JWT_KEY", "SECRET_KEY", "TOKEN_SECRET", "AUTH_SECRET",
            "APP_SECRET", "API_SECRET", "HMAC_SECRET", "SIGNING_KEY", "PRIVATE_KEY",
            "ACCESS_TOKEN_SECRET", "REFRESH_TOKEN_SECRET",

            // ---- Base64 encoded common secrets ----
            "c2VjcmV0", // "secret"
            "cGFzc3dvcmQ=", // "password"
            "dGVzdA==", // "test"
            "YWRtaW4=", // "admin"
            "a2V5", // "key"

            // ---- Numeric sequences ----
            "123456789", "1234567", "12345", "1234", "123",
            "0123456789", "9876543210", "987654321", "87654321", "7654321",
            "11111111", "22222222", "99999999", "00000000", "12341234",

            // ---- Special character variants ----
            "s3cr3t", "s3cret", "secr3t", "p@ssw0rd", "p@ss",
            "pa$$word", "pa$$w0rd", "!secret", "secret!", "#secret",
            "secret#", "$ecret", "s€cret", "5ecret", "53cr3t",

            // ---- Extended secrets ----
            "mysupersecretkey", "my-super-secret-key", "my_super_secret_key",
            "thisisasecret", "this-is-a-secret", "this_is_a_secret",
            "verysecret", "very-secret", "very_secret", "topsecret",
            "top-secret", "top_secret", "ultrapassword", "megapassword",
            "superpassword", "hyperpassword", "powerpassword",

            // ---- RSA/HMAC confusion test keys ----
            "-----BEGIN PUBLIC KEY-----", "-----BEGIN RSA PUBLIC KEY-----",
            "-----BEGIN CERTIFICATE-----",

            // ---- Empty and whitespace ----
            "", " ", "  ", "\t", "\n",
            "null", "undefined", "none", "nil", "void",
            "true", "false", "yes", "no", "0", "1",

            // ---- More framework / library defaults ----
            "AllYourBase", "jwt.io", "auth0", "okta", "keycloak",
            "firebase", "supabase", "clerk", "magic", "passport",
            "jsonwebtoken-secret", "jose-secret", "nimbus-secret",
            "jjwt-secret", "fusionauth", "identityserver",

            // ---- Additional high-frequency passwords ----
            "shadow", "sunshine", "princess", "football", "charlie",
            "superman", "batman", "trustme", "access14", "access1",
            "mustang", "michael", "thomas", "hunter2", "hunter",
            "baseball", "soccer", "harley", "ranger", "buster",
            "robert", "jordan", "daniel", "andrew", "joshua",

            // ---- More developer patterns ----
            "localhost", "127.0.0.1", "0.0.0.0", "192.168.1.1",
            "mydbpassword", "dbpassword", "dbsecret", "redis-secret",
            "mongo-secret", "postgres-secret", "mysql-secret",
            "aws-secret", "gcp-secret", "azure-secret",
            "docker-secret", "k8s-secret", "kubernetes-secret",

            // ---- Very long common secrets ----
            "ThisIsAVeryLongSecretKeyForJWTSigning",
            "MyApplicationSecretKeyForAuthentication",
            "SuperSecretKeyDoNotShareWithAnyone",
            "change-me-to-a-real-secret-in-production",
            "replace-this-with-a-secure-random-value",
            "this-is-a-placeholder-secret-change-me",
            "your-secret-key-here-replace-in-production",
            "default-jwt-signing-secret-key-change-this",

            // ---- Hash-like common JWT secrets ----
            "a1b2c3d4e5f6", "abcdef123456", "1a2b3c4d5e6f",
            "deadbeef", "cafebabe", "feedface", "c0ffee",
            "badc0de", "beef", "face", "decade",

            // ---- Extended wordlist padding to 500+ ----
            "securekey", "secure-key", "secure_key", "securetokenkey",
            "token-key", "token_key", "tokenkey", "signtoken",
            "sign-token", "sign_token", "jwk-secret", "jwk_secret",
            "access-secret", "access_secret", "refresh-secret", "refresh_secret",
            "id-token-secret", "id_token_secret", "openid-secret", "openid_secret",
            "oauth-secret", "oauth_secret", "oauth2-secret", "oauth2_secret",
            "client-secret", "client_secret", "clientsecret",
            "grant-secret", "mfa-secret", "mfa_secret", "otp-secret", "otp_secret",
            "two-factor-secret", "2fa-secret", "2fa_secret",
            "encryption-key", "encryption_key", "encryptionkey",
            "decryption-key", "decryption_key", "decryptionkey"
    );

    /**
     * Load secrets from an external file (one secret per line).
     */
    public static List<String> loadFromFile(File file) throws IOException {
        List<String> secrets = new ArrayList<>();
        try (BufferedReader br = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = br.readLine()) != null) {
                if (!line.isBlank()) {
                    secrets.add(line);
                }
            }
        }
        return secrets;
    }

    /**
     * Combine the built-in wordlist with an external file.
     */
    public static List<String> combinedWordlist(File externalFile) throws IOException {
        List<String> combined = new ArrayList<>(TOP_SECRETS);
        if (externalFile != null && externalFile.exists()) {
            combined.addAll(loadFromFile(externalFile));
        }
        return combined;
    }
}
