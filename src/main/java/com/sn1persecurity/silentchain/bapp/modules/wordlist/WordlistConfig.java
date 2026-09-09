package com.sn1persecurity.silentchain.bapp.modules.wordlist;

import java.util.List;

/**
 * Configuration options for the Wordlist Generation Engine.
 */
public record WordlistConfig(
        List<String> keywords,
        int stageLevel,              // 0 for All Progressive Stages
        int maxCount,                // 100, 1000, 10000, 100000, or custom
        int minLength,               // 0 for no min limit
        int maxLength,               // 0 for no max limit
        boolean includeCaseVariations,
        boolean includeLeetspeak,
        boolean includeYearsAndNumbers,
        boolean includeDelimiters,
        boolean includeCommonExtensions
) {
    public WordlistConfig(
            List<String> keywords,
            int maxCount,
            int minLength,
            int maxLength,
            boolean includeCaseVariations,
            boolean includeLeetspeak,
            boolean includeYearsAndNumbers,
            boolean includeDelimiters,
            boolean includeCommonExtensions
    ) {
        this(keywords, 0, maxCount, minLength, maxLength,
                includeCaseVariations, includeLeetspeak, includeYearsAndNumbers, includeDelimiters, includeCommonExtensions);
    }

    public static WordlistConfig defaults(List<String> keywords, int maxCount) {
        return new WordlistConfig(
                keywords,
                0, // All stages
                maxCount,
                0,
                0,
                true,
                true,
                true,
                true,
                true
        );
    }
}
