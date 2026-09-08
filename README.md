# 🧙‍♂️ burpinho v3.0.0 — Ultimate Local AI & Real Security Tools Suite

<div align="center">

![burpinho Logo](https://img.shields.io/badge/burpinho-v3.0.0-blue?style=for-the-badge)
[![Burp Suite](https://img.shields.io/badge/Burp_Suite-Extension-orange?style=for-the-badge&logo=burpsuite)](https://portswigger.net/burp)
[![Java](https://img.shields.io/badge/Java-17%2F21-yellow?style=for-the-badge&logo=openjdk)](https://www.java.com/)
[![Version](https://img.shields.io/badge/version-3.0.0-green?style=for-the-badge)](https://github.com/batuhansnl/burpinho)

### 🔗 🧠 ⚡ 🛡️

**Gerçek CLI Güvenlik Araçları (Recon, Nuclei, Dalfox, SQLMap, Nikto) + %100 Yerel AI ile Güçlendirilmiş Burp Suite Eklentisi**

[⬇️ **Download burpinho v3.0.0 JAR**](https://github.com/batuhansnl/burpinho/raw/main/releases/burpinho-3.0.0.jar) • [🚀 Hızlı Başlangıç](#-hızlı-başlangıç--quick-start) • [🧰 Araçlar & Kurulum](#-güvenlik-araçları-entegrasyonu--kurulum) • [⚙️ Ayarlar](#-yerel-llm-ayarları)

</div>

---

## 📥 İndirme / Download JAR

En güncel derlenmiş **v3.0.0** eklenti dosyasını indirmek için:

* 📦 **[burpinho-3.0.0.jar İndir (GitHub Direct)](https://github.com/batuhansnl/burpinho/raw/main/releases/burpinho-3.0.0.jar)**
* 📦 **[burpinho-3.0.0.jar Dosyasına Git (GitHub View)](https://github.com/batuhansnl/burpinho/blob/main/releases/burpinho-3.0.0.jar)**
* 💻 *Lokal dosya yolu:* `releases/burpinho-3.0.0.jar`

---

## 🌟 burpinho v3.0.0 ile Neler Geldi?

burpinho v3.0.0, Burp Suite içerisinden hem **gerçek Linux/macOS CLI araçlarını** tam güçle çalıştırmanızı hem de bu araçların çıktılarını **yerel yapay zeka (Ollama / OpenAI-Compatible)** ile akıllıca harmanlamanızı sağlar.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          burpinho Burp Extension                        │
│                                                                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │ 1️⃣ PASSIVE AI│  │  2️⃣ RECON    │  │  3️⃣ SCANNER  │  │  4️⃣ REPORT   │ │
│  │ Intercept &  │  │ Subfinder,   │  │ Nuclei,      │  │ Full HTML    │ │
│  │ Passive Scan │  │ Httpx, Naabu │  │ Dalfox,Sqlmap│  │ + AI Summary │ │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘ │
│         │                 │                 │                 │         │
│  ┌──────▼─────────────────▼─────────────────▼─────────────────▼───────┐ │
│  │                     ToolRunner (ProcessBuilder)                    │ │
│  │   - Gerçek CLI araçlarını yönetir, canlı çıktıları arayüze aktarır │ │
│  │   - Kurulu olmayan araçları tespit eder ve atlar                   │ │
│  └────────────────────────────────┬───────────────────────────────────┘ │
│                                   │                                     │
│                                   ▼ (İsteğe Bağlı)                      │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │             Local AI Engine (Ollama / OpenAI Compatible)           │ │
│  │   - Zafiyet Yorumlama, PoC Üretimi, Executive Summary & Risk       │ │
│  └────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 🧰 Modüller ve Özellikler

### 1️⃣ RECON Modülü (Hedef Keşfi)
* **Subdomain Enumeration:** `subfinder`, `amass`, `assetfinder`
* **DNS Resolution:** `dnsx` ile yaşayan host filtreleme
* **HTTP Probe & Tech:** `httpx` (title, web server, tech stack)
* **Port Tarama:** `naabu` (en popüler portlar / tam aralık)
* **WAF Tespiti:** `wafw00f` ile hedef WAF analizi
* **Teknoloji Parmak İzi:** `whatweb`
* **Web Crawling:** `katana`

### 2️⃣ SCANNER Modülü (Zafiyet Tarama)
* **Genel & CVE Tarama:** `nuclei` (community ve custom template desteği)
* **XSS:** `dalfox` ile reflected / parameter XSS analizi
* **SQL Injection:** `sqlmap` akıllı batch modu
* **Web Server Scanner:** `nikto`
* **Fuzzing & Keşif:** `ffuf`

### 3️⃣ EXPLOIT Modülü (Hibrit)
* **Exploit-DB Arama:** `searchsploit` ile teknoloji/CVE bazlı offline arama
* **AI Exploit & Payload Önerisi:** Tespit edilen zafiyete özel güvenli doğrulama payload'ları
* **AI PoC Üretici:** Otomatik Python ve cURL test betikleri

### 4️⃣ REPORT Modülü (Profesyonel Raporlama)
* Tüm Recon, Scanner ve Passive AI bulgularını modern **Dark Theme HTML** raporuna döker.
* İsteğe bağlı olarak yerel AI'dan **Executive Summary**, **Risk Skorlaması** ve **Uyumluluk (PCI-DSS, ISO 27001)** değerlendirmesi ekler.

### 5️⃣ PASSIVE AI Modülü (Trafik Analizi)
* Proxy / Repeater trafiğini arka planda analiz eder, OWASP Top 10 ve CWE bazlı potansiyel riskleri tespit eder.

---

## 📦 Güvenlik Araçları Entegrasyonu & Kurulum

Eklenti, sisteminizde hangi araçların kurulu olduğunu otomatik olarak denetler (**Settings → Tools** sekmesinden görebilirsiniz). Kurulu olmayan araçlar hata vermeden atlanır.

Araçları hızlıca kurmak için:

### Go Tabanlı Araçlar:
```bash
# Recon araçları
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/tomnomnom/assetfinder@latest

# Scanner & Fuzzing araçları
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/hahwul/dalfox/v2@latest
go install -v github.com/ffuf/ffuf/v2@latest
```

### Python / Paket Yöneticisi Araçları:
```bash
# macOS (Homebrew)
brew install sqlmap nikto whatweb
pip3 install wafw00f

# Linux (Debian/Ubuntu/Kali)
sudo apt update && sudo apt install -y sqlmap nikto whatweb exploitdb
pip3 install wafw00f
```

---

## 🚀 Hızlı Başlangıç / Quick Start

### 1. Eklentiyi Burp Suite'e Ekleyin
1. **[burpinho-3.0.0.jar](https://github.com/batuhansnl/burpinho/raw/main/releases/burpinho-3.0.0.jar)** dosyasını indirin.
2. Burp Suite: **Extensions** → **Installed** → **Add**
3. **Extension Type:** `Java`
4. `burpinho-3.0.0.jar` dosyasını seçip **Next** deyin.

### 2. Yerel LLM Ayarları
1. Burp menüsünde **burpinho** sekmesine gelin → **⚙ Settings**
2. **AI Provider:** `OpenAI Compatible (Local/Custom)` veya `Ollama (Local)` seçin.
3. **API URL:** Örnek: `http://localhost:11434` (Ollama) veya `http://localhost:8000/v1` (vLLM / LM Studio / Internal LLM).
4. **Test Connection** butonuna basarak bağlantıyı onaylayın.

### 3. Sağ Tık (Context Menu) Kolaylığı
Burp Suite HTTP History veya Repeater'da herhangi bir isteğe sağ tıklayarak:
* **burpinho → 🔍 Recon Target Domain**: Hedef domaini tek tıkla Recon sekmesine aktarır.
* **burpinho → 🎯 Deep Vulnerability Scan**: Seçilen URL'leri Scanner sekmesine aktarır.
* **burpinho → Analyze Request (AI)**: İsteği doğrudan yerel yapay zeka analizine gönderir.

---

## 🛠️ Kaynak Koddan Derleme (Build from Source)

```bash
git clone https://github.com/batuhansnl/burpinho.git
cd burpinho

# Gradle ile derleyin
gradle shadowJar
```

Derlenen JAR dosyası `build/libs/burpinho-3.0.0.jar` ve `releases/burpinho-3.0.0.jar` dizinlerinde yer alır.

---

## 📄 Lisans
Bu proje açık kaynak ve topluluk kullanımı için geliştirilmiştir.