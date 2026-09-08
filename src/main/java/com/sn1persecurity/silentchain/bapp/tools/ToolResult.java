package com.sn1persecurity.silentchain.bapp.tools;

import java.util.List;

/**
 * Immutable result of a single CLI tool execution.
 *
 * @param toolName    which tool produced this result
 * @param exitCode    process exit code (0 = success)
 * @param stdout      raw standard output
 * @param stderr      raw standard error
 * @param durationMs  wall-clock execution time in milliseconds
 * @param timedOut    true if the process was killed due to timeout
 * @param parsedLines stdout split into non-empty trimmed lines
 */
public record ToolResult(
        String toolName,
        int exitCode,
        String stdout,
        String stderr,
        long durationMs,
        boolean timedOut,
        List<String> parsedLines
) {

    public boolean ok() {
        return exitCode == 0 && !timedOut;
    }

    public boolean hasOutput() {
        return stdout != null && !stdout.isBlank();
    }

    /** Number of result lines. */
    public int lineCount() {
        return parsedLines != null ? parsedLines.size() : 0;
    }

    /** Short human-readable summary for logging. */
    public String summary() {
        if (timedOut) return toolName + ": timed out";
        if (exitCode != 0) return toolName + ": exit " + exitCode;
        return toolName + ": " + lineCount() + " result(s) in " + durationMs + "ms";
    }

    /** Factory for a failed / not-installed tool. */
    public static ToolResult notInstalled(String toolName) {
        return new ToolResult(toolName, -1, "", toolName + " is not installed", 0, false, List.of());
    }

    /** Factory for a skipped tool. */
    public static ToolResult skipped(String toolName, String reason) {
        return new ToolResult(toolName, -2, "", reason, 0, false, List.of());
    }
}
