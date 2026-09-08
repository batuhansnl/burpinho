package com.sn1persecurity.silentchain.bapp.util;

import burp.api.montoya.MontoyaApi;

import com.sn1persecurity.silentchain.bapp.SilentchainExtension;

/**
 * ASCII logo block printed to Burp's Extensions Output on load
 * (Community silentchain_ai_community.py:2054-2075), updated for the BApp
 * edition with the mandatory non-affiliation line.
 */
public final class Banner {

    private Banner() {}

    public static void print(MontoyaApi api) {
        String v = SilentchainExtension.EXTENSION_VERSION;
        String banner = String.join("\n",
            "=================================================================",
            "",
            "     🧙‍♂️ burpinho - Local AI Security for Burp Suite",
            "     -------------------------------------------------",
            "     AI-Powered OWASP Top 10 Vulnerability Scanning",
            "",
            "     v" + v + "  |  Local First • Private • Customizable",
            "",
            "     Supported Local Providers:",
            "       - OpenAI Compatible (vLLM, TGI, LocalAI, Corporate LLM)",
            "       - Ollama (Local)",
            "",
            "     https://github.com/batuhansnl/burpinho",
            "",
            "================================================================="
        );
        api.logging().logToOutput(banner);
    }
}
