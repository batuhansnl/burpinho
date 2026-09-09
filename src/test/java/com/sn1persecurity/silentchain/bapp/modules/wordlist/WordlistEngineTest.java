package com.sn1persecurity.silentchain.bapp.modules.wordlist;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class WordlistEngineTest {

    @Test
    public void testBasicGenerationAndCountLimits() {
        WordlistEngine engine = new WordlistEngine();

        // Test 100 limit
        WordlistConfig config100 = new WordlistConfig(
                List.of("admin", "portal"),
                0, // All stages
                100,
                0,
                0,
                true,
                true,
                true,
                true,
                true
        );
        List<String> list100 = engine.generate(config100);
        assertNotNull(list100);
        assertTrue(list100.size() <= 100, "Size should be <= 100 but was " + list100.size());
        assertTrue(list100.size() > 10, "Should generate multiple entries");

        // Test 1000 limit
        WordlistConfig config1000 = new WordlistConfig(
                List.of("admin", "test", "company"),
                0,
                1000,
                0,
                0,
                true,
                true,
                true,
                true,
                true
        );
        List<String> list1000 = engine.generate(config1000);
        assertTrue(list1000.size() <= 1000);
        assertTrue(list1000.size() > 100);
    }

    @Test
    public void testCharacterLengthConstraints() {
        WordlistEngine engine = new WordlistEngine();

        int minLen = 5;
        int maxLen = 8;
        WordlistConfig config = new WordlistConfig(
                List.of("admin", "portal", "security"),
                0,
                1000,
                minLen,
                maxLen,
                true,
                true,
                true,
                true,
                true
        );

        List<String> results = engine.generate(config);
        assertFalse(results.isEmpty(), "Results should not be empty");

        for (String w : results) {
            assertTrue(w.length() >= minLen, "Word '" + w + "' is shorter than min " + minLen);
            assertTrue(w.length() <= maxLen, "Word '" + w + "' is longer than max " + maxLen);
        }
    }

    @Test
    public void testIndividualStages() {
        WordlistEngine engine = new WordlistEngine();
        List<String> kw = List.of("sirket");

        // Stage 1
        List<String> stage1 = engine.generate(new WordlistConfig(kw, 1, 500, 0, 0, true, true, true, true, true));
        assertFalse(stage1.isEmpty());
        assertTrue(stage1.contains("sirket") || stage1.contains("Sirket") || stage1.contains("SIRKET"));

        // Stage 2
        List<String> stage2 = engine.generate(new WordlistConfig(kw, 2, 500, 0, 0, true, true, true, true, true));
        assertFalse(stage2.isEmpty());

        // Stage 3 (Leet)
        List<String> stage3 = engine.generate(new WordlistConfig(kw, 3, 500, 0, 0, true, true, true, true, true));
        assertFalse(stage3.isEmpty());

        // Stage 4 (Deep)
        List<String> stage4 = engine.generate(new WordlistConfig(kw, 4, 500, 0, 0, true, true, true, true, true));
        assertFalse(stage4.isEmpty());
    }
}
