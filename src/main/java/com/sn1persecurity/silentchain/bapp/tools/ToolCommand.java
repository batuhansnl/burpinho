package com.sn1persecurity.silentchain.bapp.tools;

import java.util.List;

/**
 * Immutable command descriptor for an external CLI tool invocation.
 *
 * @param name           human-readable tool name (e.g. "subfinder", "nuclei")
 * @param command        full command line as list (e.g. ["subfinder", "-d", "example.com"])
 * @param timeoutSeconds maximum execution time before the process is killed
 * @param outputFormat   expected output format for parsing
 * @param pipeInput      optional stdin input (piped into the process)
 */
public record ToolCommand(
        String name,
        List<String> command,
        int timeoutSeconds,
        OutputFormat outputFormat,
        String pipeInput
) {

    public enum OutputFormat {
        JSON,        // one JSON object per line (jsonl) or single JSON
        TEXT,        // plain text, one result per line
        CSV          // comma-separated
    }

    /** Convenience: no stdin pipe. */
    public ToolCommand(String name, List<String> command, int timeoutSeconds, OutputFormat outputFormat) {
        this(name, command, timeoutSeconds, outputFormat, null);
    }

    /** Convenience: text output, no pipe, default 120s timeout. */
    public ToolCommand(String name, List<String> command) {
        this(name, command, 120, OutputFormat.TEXT, null);
    }
}
