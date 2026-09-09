package com.sn1persecurity.silentchain.bapp.modules.wordlist;

import java.util.*;
import java.util.function.Consumer;

/**
 * 4-Stage Advanced Wordlist & Dictionary Generation Engine.
 *
 * Stage 1: Basic mutations (Case transformations, single digits, current years, basic punctuation).
 * Stage 2: Combinations & Delimiters (Cross-keyword pairing, web & IT roles, file extensions, date formats).
 * Stage 3: Leetspeak & Special Symbols (Systematic leet substitutions, symbol wrapping, password patterns).
 * Stage 4: Deep Permutations & Fuzzing (3-way keyword combinations, reversed words, duplication, keyboard walks, hex indices).
 */
public class WordlistEngine {

    private volatile boolean cancelled = false;
    private Consumer<String> logCallback;
    private Consumer<Integer> progressCallback;

    public void setLogCallback(Consumer<String> logCallback) {
        this.logCallback = logCallback;
    }

    public void setProgressCallback(Consumer<Integer> progressCallback) {
        this.progressCallback = progressCallback;
    }

    public void cancel() {
        this.cancelled = true;
    }

    public boolean isCancelled() {
        return cancelled;
    }

    private void log(String msg) {
        if (logCallback != null) logCallback.accept(msg);
    }

    /**
     * Executes the generation pipeline according to the provided config.
     * Returns a deduplicated list of generated words respecting min/max length and max count.
     */
    public List<String> generate(WordlistConfig config) {
        this.cancelled = false;
        Set<String> resultSet = new LinkedHashSet<>();

        List<String> rawKeywords = config.keywords() != null ? config.keywords() : List.of();
        List<String> cleanedKeywords = new ArrayList<>();
        for (String k : rawKeywords) {
            String trimmed = k.trim();
            if (!trimmed.isEmpty()) {
                cleanedKeywords.add(trimmed);
            }
        }

        if (cleanedKeywords.isEmpty()) {
            log("[!] Hiçbir anahtar kelime verilmedi.");
            return List.of();
        }

        int targetCount = config.maxCount() > 0 ? config.maxCount() : 1000;
        int stage = config.stageLevel(); // 0 = all stages, 1, 2, 3, 4

        log("[*] Wordlist üretimi başlatılıyor... Hedef: " + targetCount + " kelime, Aşama: " + (stage == 0 ? "Tüm Aşamalar (1-4)" : "Aşama " + stage));

        // Add raw keywords first
        for (String kw : cleanedKeywords) {
            addCandidate(resultSet, kw, config, targetCount);
            if (resultSet.size() >= targetCount || cancelled) break;
        }

        // ==========================================
        // STAGE 1: Temel Varyasyonlar (Basic)
        // ==========================================
        if ((stage == 0 || stage == 1) && resultSet.size() < targetCount && !cancelled) {
            log("[*] Aşama 1 (Temel Varyasyonlar & Yıllar) çalıştırılıyor...");
            runStage1(cleanedKeywords, resultSet, config, targetCount);
            reportProgress(resultSet.size());
        }

        // ==========================================
        // STAGE 2: Kombinasyonlar & Ayırıcılar
        // ==========================================
        if ((stage == 0 || stage == 2) && resultSet.size() < targetCount && !cancelled) {
            log("[*] Aşama 2 (Kelimeler Arası Kombinasyonlar, Roller & Uzantılar) çalıştırılıyor...");
            runStage2(cleanedKeywords, resultSet, config, targetCount);
            reportProgress(resultSet.size());
        }

        // ==========================================
        // STAGE 3: Leetspeak & Özel Karakterler
        // ==========================================
        if ((stage == 0 || stage == 3) && resultSet.size() < targetCount && !cancelled) {
            log("[*] Aşama 3 (Leetspeak Dönüşümleri & Semboller) çalıştırılıyor...");
            runStage3(cleanedKeywords, resultSet, config, targetCount);
            reportProgress(resultSet.size());
        }

        // ==========================================
        // STAGE 4: Kapsamlı & Derin Mutasyonlar
        // ==========================================
        if ((stage == 0 || stage == 4) && resultSet.size() < targetCount && !cancelled) {
            log("[*] Aşama 4 (3'lü Permütasyonlar, Tersine Çevirme & Fuzzing Kalıpları) çalıştırılıyor...");
            runStage4(cleanedKeywords, resultSet, config, targetCount);
            reportProgress(resultSet.size());
        }

        log("[+] Wordlist üretimi tamamlandı! Toplam benzersiz kelime sayısı: " + resultSet.size());
        return new ArrayList<>(resultSet);
    }

    private void reportProgress(int count) {
        if (progressCallback != null) progressCallback.accept(count);
    }

    // =========================================================================
    //  STAGE 1: Basic Mutations
    // =========================================================================
    private void runStage1(List<String> keywords, Set<String> results, WordlistConfig config, int max) {
        List<String> years = List.of("2020", "2021", "2022", "2023", "2024", "2025", "2026", "2027", "2028", "1990", "1995", "2000");
        List<String> simpleNumbers = List.of("1", "12", "123", "1234", "12345", "123456", "01", "00", "007", "99", "69");
        List<String> basicSymbols = List.of("!", "@", "#", "$", ".", "_", "-");

        for (String kw : keywords) {
            if (results.size() >= max || cancelled) break;

            // 1. Case variations
            List<String> cases = getCaseVariations(kw, config.includeCaseVariations());
            for (String c : cases) {
                addCandidate(results, c, config, max);

                if (config.includeYearsAndNumbers()) {
                    // + Years
                    for (String y : years) {
                        addCandidate(results, c + y, config, max);
                        addCandidate(results, y + c, config, max);
                        addCandidate(results, c + y.substring(2), config, max); // e.g. kw24, kw25
                        if (results.size() >= max || cancelled) return;
                    }

                    // + Simple numbers
                    for (String num : simpleNumbers) {
                        addCandidate(results, c + num, config, max);
                        addCandidate(results, num + c, config, max);
                        if (results.size() >= max || cancelled) return;
                    }
                }

                // + Symbols
                if (config.includeDelimiters()) {
                    for (String sym : basicSymbols) {
                        addCandidate(results, c + sym, config, max);
                        addCandidate(results, sym + c, config, max);
                        if (config.includeYearsAndNumbers()) {
                            addCandidate(results, c + "123" + sym, config, max);
                            addCandidate(results, c + "2025" + sym, config, max);
                            addCandidate(results, c + "2026" + sym, config, max);
                        }
                        if (results.size() >= max || cancelled) return;
                    }
                }
            }
        }
    }

    // =========================================================================
    //  STAGE 2: Combinations & Delimiters & IT Roles
    // =========================================================================
    private void runStage2(List<String> keywords, Set<String> results, WordlistConfig config, int max) {
        List<String> delimiters = config.includeDelimiters() ? List.of("", "_", "-", ".", "@", "+", "/", "$") : List.of("");
        List<String> roles = List.of(
                "admin", "root", "user", "api", "v1", "v2", "test", "dev", "prod", "stage", "staging",
                "db", "auth", "login", "portal", "config", "app", "internal", "backup", "secret",
                "sys", "service", "master", "guest", "demo", "corp", "web", "server"
        );
        List<String> extensions = config.includeCommonExtensions() ? List.of(
                ".php", ".json", ".env", ".bak", ".sql", ".zip", ".tar.gz", ".yaml", ".xml",
                ".conf", ".log", ".txt", ".asp", ".aspx", ".jsp", ".do", ".action", ".html", ".js"
        ) : List.of();

        // 1. Cross-Keyword Combinations (kw1 + sep + kw2)
        for (int i = 0; i < keywords.size(); i++) {
            for (int j = 0; j < keywords.size(); j++) {
                if (results.size() >= max || cancelled) return;
                String k1 = keywords.get(i);
                String k2 = keywords.get(j);

                for (String sep : delimiters) {
                    addCandidate(results, k1 + sep + k2, config, max);
                    addCandidate(results, capitalize(k1) + sep + capitalize(k2), config, max);
                    addCandidate(results, k1.toLowerCase() + sep + k2.toLowerCase(), config, max);
                    addCandidate(results, k1.toUpperCase() + sep + k2.toUpperCase(), config, max);

                    if (config.includeYearsAndNumbers()) {
                        addCandidate(results, k1 + sep + k2 + "2025", config, max);
                        addCandidate(results, k1 + sep + k2 + "2026", config, max);
                        addCandidate(results, k1 + sep + k2 + "123", config, max);
                        addCandidate(results, k1 + sep + k2 + "!", config, max);
                    }
                    if (results.size() >= max || cancelled) return;
                }
            }
        }

        // 2. Keyword + IT / Web Roles
        for (String kw : keywords) {
            for (String role : roles) {
                if (results.size() >= max || cancelled) return;
                for (String sep : delimiters) {
                    addCandidate(results, kw + sep + role, config, max);
                    addCandidate(results, role + sep + kw, config, max);
                    addCandidate(results, capitalize(kw) + sep + capitalize(role), config, max);
                    addCandidate(results, kw.toLowerCase() + sep + role.toLowerCase(), config, max);

                    if (config.includeYearsAndNumbers()) {
                        addCandidate(results, kw + sep + role + "1", config, max);
                        addCandidate(results, kw + sep + role + "2025", config, max);
                        addCandidate(results, kw + sep + role + "2026", config, max);
                    }
                    if (results.size() >= max || cancelled) return;
                }

                // File extensions (Path Fuzzing ready)
                for (String ext : extensions) {
                    addCandidate(results, kw + ext, config, max);
                    addCandidate(results, kw + "_" + role + ext, config, max);
                    addCandidate(results, kw + "-" + role + ext, config, max);
                    addCandidate(results, role + "_" + kw + ext, config, max);
                    if (results.size() >= max || cancelled) return;
                }
            }
        }
    }

    // =========================================================================
    //  STAGE 3: Leetspeak & Special Symbols
    // =========================================================================
    private void runStage3(List<String> keywords, Set<String> results, WordlistConfig config, int max) {
        if (!config.includeLeetspeak()) {
            return;
        }

        List<String> specialPunct = List.of("!", "@", "#", "$", "%", "&", "*", "?", "!!", "@@");

        for (String kw : keywords) {
            if (results.size() >= max || cancelled) return;

            Set<String> leetVariations = generateLeetVariants(kw);
            for (String leet : leetVariations) {
                addCandidate(results, leet, config, max);

                if (config.includeYearsAndNumbers()) {
                    addCandidate(results, leet + "123", config, max);
                    addCandidate(results, leet + "2024", config, max);
                    addCandidate(results, leet + "2025", config, max);
                    addCandidate(results, leet + "2026", config, max);
                    addCandidate(results, "123" + leet, config, max);
                }

                if (config.includeDelimiters()) {
                    for (String sym : specialPunct) {
                        addCandidate(results, leet + sym, config, max);
                        addCandidate(results, sym + leet, config, max);
                        addCandidate(results, sym + leet + sym, config, max);

                        if (config.includeYearsAndNumbers()) {
                            addCandidate(results, leet + "2025" + sym, config, max);
                            addCandidate(results, leet + "2026" + sym, config, max);
                            addCandidate(results, sym + leet + "2025", config, max);
                            addCandidate(results, sym + leet + "123" + sym, config, max);
                        }
                        if (results.size() >= max || cancelled) return;
                    }
                }
            }
        }
    }

    // =========================================================================
    //  STAGE 4: Deep Permutations & Fuzzing (3-way, reversed, duplication, walks)
    // =========================================================================
    private void runStage4(List<String> keywords, Set<String> results, WordlistConfig config, int max) {
        List<String> walks = List.of("qwe", "qwert", "1q2w3e", "abc", "xyz", "pass", "admin", "p@ss");
        List<String> hexes = List.of("_01", "_02", "_03", "_00", "_ff", "_v1", "_v2", "_old", "_new", "_bak", "_temp", "_test");

        for (String kw : keywords) {
            if (results.size() >= max || cancelled) return;

            // 1. Reversed
            String rev = new StringBuilder(kw).reverse().toString();
            addCandidate(results, rev, config, max);
            addCandidate(results, rev + "123", config, max);
            addCandidate(results, rev + "2025", config, max);

            // 2. Duplication (kw + kw)
            addCandidate(results, kw + kw, config, max);
            addCandidate(results, kw + "_" + kw, config, max);
            addCandidate(results, kw + "-" + kw, config, max);

            // 3. Keyboard walks appended
            for (String walk : walks) {
                addCandidate(results, kw + walk, config, max);
                addCandidate(results, capitalize(kw) + walk, config, max);
                addCandidate(results, walk + kw, config, max);
                if (results.size() >= max || cancelled) return;
            }

            // 4. Hex & Version indices
            for (String hx : hexes) {
                addCandidate(results, kw + hx, config, max);
                addCandidate(results, kw + hx + ".bak", config, max);
                addCandidate(results, kw + hx + ".sql", config, max);
                if (results.size() >= max || cancelled) return;
            }
        }

        // 5. 3-way combinations (if at least 2 keywords)
        if (keywords.size() >= 2) {
            for (int i = 0; i < keywords.size(); i++) {
                for (int j = 0; j < keywords.size(); j++) {
                    for (int k = 0; k < keywords.size(); k++) {
                        if (results.size() >= max || cancelled) return;
                        String w1 = keywords.get(i);
                        String w2 = keywords.get(j);
                        String w3 = keywords.get(k);

                        addCandidate(results, w1 + "_" + w2 + "_" + w3, config, max);
                        addCandidate(results, w1 + "-" + w2 + "-" + w3, config, max);
                        addCandidate(results, w1 + "." + w2 + "." + w3, config, max);
                        addCandidate(results, capitalize(w1) + capitalize(w2) + capitalize(w3), config, max);
                        if (results.size() >= max || cancelled) return;
                    }
                }
            }
        }
    }

    // =========================================================================
    //  Candidate validation & insertion
    // =========================================================================
    private void addCandidate(Set<String> set, String candidate, WordlistConfig config, int max) {
        if (candidate == null || candidate.isEmpty() || set.size() >= max || cancelled) {
            return;
        }

        // Length validation
        if (config.minLength() > 0 && candidate.length() < config.minLength()) {
            return;
        }
        if (config.maxLength() > 0 && candidate.length() > config.maxLength()) {
            return;
        }

        set.add(candidate);
    }

    // =========================================================================
    //  Transformation Helpers
    // =========================================================================
    private List<String> getCaseVariations(String word, boolean enable) {
        if (!enable) return List.of(word);
        List<String> list = new ArrayList<>();
        list.add(word.toLowerCase());
        list.add(word.toUpperCase());
        list.add(capitalize(word));
        list.add(toggleCase(word));
        return list;
    }

    private String capitalize(String str) {
        if (str == null || str.isEmpty()) return str;
        return Character.toUpperCase(str.charAt(0)) + (str.length() > 1 ? str.substring(1).toLowerCase() : "");
    }

    private String toggleCase(String str) {
        if (str == null || str.isEmpty()) return str;
        StringBuilder sb = new StringBuilder();
        for (char c : str.toCharArray()) {
            if (Character.isUpperCase(c)) sb.append(Character.toLowerCase(c));
            else if (Character.isLowerCase(c)) sb.append(Character.toUpperCase(c));
            else sb.append(c);
        }
        return sb.toString();
    }

    private Set<String> generateLeetVariants(String word) {
        Set<String> set = new LinkedHashSet<>();
        String lower = word.toLowerCase();

        // 1. Full standard leet
        String fullLeet = lower
                .replace('a', '4')
                .replace('e', '3')
                .replace('i', '1')
                .replace('o', '0')
                .replace('s', '5')
                .replace('t', '7');
        set.add(fullLeet);
        set.add(capitalize(fullLeet));

        // 2. Full symbol leet
        String symbolLeet = lower
                .replace('a', '@')
                .replace('e', '3')
                .replace('i', '!')
                .replace('o', '0')
                .replace('s', '$')
                .replace('t', '+');
        set.add(symbolLeet);

        // 3. Single char replacements
        set.add(lower.replace('a', '4'));
        set.add(lower.replace('a', '@'));
        set.add(lower.replace('e', '3'));
        set.add(lower.replace('i', '1'));
        set.add(lower.replace('i', '!'));
        set.add(lower.replace('o', '0'));
        set.add(lower.replace('s', '5'));
        set.add(lower.replace('s', '$'));
        set.add(lower.replace('t', '7'));

        // 4. Capitalized single char replacements
        String cap = capitalize(word);
        set.add(cap.replace('a', '4').replace('A', '4'));
        set.add(cap.replace('a', '@').replace('A', '@'));
        set.add(cap.replace('e', '3').replace('E', '3'));
        set.add(cap.replace('o', '0').replace('O', '0'));
        set.add(cap.replace('s', '$').replace('S', '$'));

        return set;
    }
}
