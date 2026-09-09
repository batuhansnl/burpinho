package com.sn1persecurity.silentchain.bapp.tools;

import burp.api.montoya.MontoyaApi;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

/**
 * Executes external CLI tools via {@link ProcessBuilder} and captures output.
 *
 * This is the core engine that all modules (Recon, Scanner, Exploit) use to run
 * real security tools like subfinder, nuclei, httpx, naabu, etc.
 *
 * Thread-safe: each invocation creates its own Process instance.
 */
public class ToolRunner {

    private final MontoyaApi api;
    private final ToolRegistry registry;

    public ToolRunner(MontoyaApi api, ToolRegistry registry) {
        this.api = api;
        this.registry = registry;
    }

    /**
     * Run a tool synchronously and return the result.
     * Blocks until the tool finishes or times out.
     */
    public ToolResult run(ToolCommand command) {
        return run(command, null);
    }

    /**
     * Run a tool synchronously with a live output callback.
     * The callback receives each line of stdout as it is produced.
     */
    public ToolResult run(ToolCommand command, Consumer<String> liveOutput) {
        String toolName = command.name();

        // Check if the tool is installed
        String exePath = registry.getPath(toolName);
        if (exePath == null || exePath.isEmpty()) {
            api.logging().logToError("ToolRunner: " + toolName + " is not installed.");
            return ToolResult.notInstalled(toolName);
        }

        long startTime = System.currentTimeMillis();

        try {
            List<String> cmd = new ArrayList<>(command.command());
            cmd.set(0, exePath);

            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.redirectErrorStream(false);
            pb.environment().putAll(System.getenv());

            String userHome = System.getProperty("user.home", "");
            String envPath = pb.environment().getOrDefault("PATH", "");
            pb.environment().put("PATH",
                    "/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:"
                    + userHome + "/go/bin:"
                    + userHome + "/.local/bin:"
                    + userHome + "/.cargo/bin:"
                    + envPath);

            api.logging().logToOutput("ToolRunner: starting " + toolName + " → " + String.join(" ", cmd));

            Process process = pb.start();

            // If there's pipe input, write it to stdin
            if (command.pipeInput() != null && !command.pipeInput().isEmpty()) {
                try (OutputStream stdin = process.getOutputStream()) {
                    stdin.write(command.pipeInput().getBytes(StandardCharsets.UTF_8));
                    stdin.flush();
                }
            }

            // Read stdout in a separate thread to avoid blocking
            StringBuilder stdoutBuilder = new StringBuilder();
            List<String> parsedLines = new ArrayList<>();
            Thread stdoutReader = new Thread(() -> {
                try (BufferedReader reader = new BufferedReader(
                        new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        stdoutBuilder.append(line).append("\n");
                        String trimmed = line.trim();
                        if (!trimmed.isEmpty()) {
                            synchronized (parsedLines) {
                                parsedLines.add(trimmed);
                            }
                            if (liveOutput != null) {
                                liveOutput.accept(trimmed);
                            }
                        }
                    }
                } catch (IOException e) {
                    // Process ended, normal
                }
            }, "toolrunner-stdout-" + toolName);
            stdoutReader.setDaemon(true);
            stdoutReader.start();

            // Read stderr
            StringBuilder stderrBuilder = new StringBuilder();
            Thread stderrReader = new Thread(() -> {
                try (BufferedReader reader = new BufferedReader(
                        new InputStreamReader(process.getErrorStream(), StandardCharsets.UTF_8))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        stderrBuilder.append(line).append("\n");
                    }
                } catch (IOException e) {
                    // Process ended, normal
                }
            }, "toolrunner-stderr-" + toolName);
            stderrReader.setDaemon(true);
            stderrReader.start();

            // Wait for process to complete (with timeout)
            boolean finished = process.waitFor(command.timeoutSeconds(), TimeUnit.SECONDS);

            if (!finished) {
                process.destroyForcibly();
                process.waitFor(5, TimeUnit.SECONDS);
                long duration = System.currentTimeMillis() - startTime;

                api.logging().logToError("ToolRunner: " + toolName + " timed out after " + command.timeoutSeconds() + "s");

                // Wait for readers to drain
                stdoutReader.join(2000);
                stderrReader.join(2000);

                synchronized (parsedLines) {
                    return new ToolResult(toolName, -1, stdoutBuilder.toString(),
                            stderrBuilder.toString(), duration, true, new ArrayList<>(parsedLines));
                }
            }

            // Wait for reader threads to finish
            stdoutReader.join(5000);
            stderrReader.join(5000);

            long duration = System.currentTimeMillis() - startTime;
            int exitCode = process.exitValue();

            synchronized (parsedLines) {
                ToolResult result = new ToolResult(toolName, exitCode, stdoutBuilder.toString(),
                        stderrBuilder.toString(), duration, false, new ArrayList<>(parsedLines));

                api.logging().logToOutput("ToolRunner: " + result.summary());

                if (exitCode != 0 && !stderrBuilder.isEmpty()) {
                    api.logging().logToError("ToolRunner: " + toolName + " stderr: "
                            + truncate(stderrBuilder.toString(), 500));
                }

                return result;
            }

        } catch (IOException e) {
            long duration = System.currentTimeMillis() - startTime;
            api.logging().logToError("ToolRunner: failed to start " + toolName + ": " + e.getMessage());
            return new ToolResult(toolName, -1, "", e.getMessage(), duration, false, List.of());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            long duration = System.currentTimeMillis() - startTime;
            return new ToolResult(toolName, -1, "", "interrupted", duration, false, List.of());
        }
    }

    /**
     * Run a simple command and return stdout as a single string.
     * Useful for quick checks like "subfinder --version".
     */
    public String runQuick(String... command) {
        try {
            ProcessBuilder pb = new ProcessBuilder(command);
            pb.redirectErrorStream(true);

            String path = pb.environment().getOrDefault("PATH", "");
            pb.environment().put("PATH",
                    path + ":/usr/local/bin:/usr/bin:/opt/homebrew/bin"
                    + ":" + System.getProperty("user.home") + "/go/bin"
                    + ":" + System.getProperty("user.home") + "/.local/bin");

            Process p = pb.start();
            String output = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
            p.waitFor(10, TimeUnit.SECONDS);
            return output;
        } catch (Throwable t) {
            return "";
        }
    }

    /**
     * Helper to pipe input into a tool. Example: echo domains | httpx
     */
    public ToolResult runWithPipe(String toolName, List<String> args, String input, int timeoutSeconds) {
        return run(new ToolCommand(toolName, args, timeoutSeconds, ToolCommand.OutputFormat.TEXT, input));
    }

    private static String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() <= max ? s : s.substring(0, max) + "...";
    }
}
