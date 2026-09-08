package com.sn1persecurity.silentchain.bapp.tools;

/**
 * Metadata about a supported external tool.
 *
 * @param name        executable name (e.g. "subfinder")
 * @param description short human-readable description
 * @param category    which module uses this tool
 * @param installCmd  how to install (shown to user)
 * @param required    if true, module cannot run without it
 */
public record ToolInfo(
        String name,
        String description,
        Category category,
        String installCmd,
        boolean required
) {

    public enum Category {
        RECON,
        SCANNER,
        EXPLOIT,
        UTILITY
    }
}
