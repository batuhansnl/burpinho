# 🧙‍♂️ burpinho v3.2.0 — 100% Self-Contained Local AI & Security Suite

<div align="center">

![burpinho Logo](https://img.shields.io/badge/burpinho-v3.2.0-blue?style=for-the-badge)
[![Burp Suite](https://img.shields.io/badge/Burp_Suite-Extension-orange?style=for-the-badge&logo=burpsuite)](https://portswigger.net/burp)
[![Java](https://img.shields.io/badge/Java-17%2F21-yellow?style=for-the-badge&logo=openjdk)](https://www.java.com/)
[![OS Support](https://img.shields.io/badge/OS-Windows%20%7C%20macOS%20%7C%20Linux-green?style=for-the-badge)](https://github.com/batuhansnl/burpinho)
[![Version](https://img.shields.io/badge/version-3.2.0-brightgreen?style=for-the-badge)](https://github.com/batuhansnl/burpinho)

### 🔗 🧠 ⚡ 🛡️

**9 Ayrı Özel Modül Menüsü • %100 Dahili Saf Java Güvenlik Motorları • IP / CIDR Network Scanner • Subdomain IP & Port Keşfi • Canlı Loglar • Yerel AI**  
*(Sıfır Dış Kurulum: Go, Python veya Harici Tool Gerektirmez — Şirket & Windows Bilgisayarları İçin %100 Uyumlu)*

[⬇️ **Download burpinho v3.2.0 JAR**](https://github.com/batuhansnl/burpinho/raw/main/releases/burpinho-3.2.0.jar) • [🚀 Hızlı Başlangıç](#-hızlı-başlangıç--quick-start) • [🧰 Modüller](#-9-özel-bağımsız-modül-menüsü) • [⚙️ Ayarlar](#-yerel-llm-ayarları)

</div>

---

## 📥 İndirme / Download JAR

En güncel tek parça **v3.2.0** eklenti dosyasını indirmek için:

* 📦 **[burpinho-3.2.0.jar İndir (GitHub Direct)](https://github.com/batuhansnl/burpinho/raw/main/releases/burpinho-3.2.0.jar)**
* 📦 **[burpinho-3.2.0.jar Dosyasına Git (GitHub View)](https://github.com/batuhansnl/burpinho/blob/main/releases/burpinho-3.2.0.jar)**
* 💻 *Lokal dosya yolu:* `releases/burpinho-3.2.0.jar` ve `/Users/batuhansenel/Downloads/burpinho-3.2.0.jar`

---

## 🌟 Neden burpinho v3.2.0?

Kısıtlı şirket ve banka bilgisayarlarında admin yetkisi olmaması, dışarıdan `go install`, `pip install`, `brew install` yapılamaması veya güvenlik politikaları sebebiyle harici binary (.exe) çalıştırılamaması problemlerini **%100 dahili Saf Java motorları** ile çözdük.

Tüm araçlar birbirinden bağımsız **9 ayrı menü/tab** olarak ayrılmış olup, her birinin kendine özel thread, timeout, port profili, wordlist ve payload konfigürasyonları ve anlık **Canlı İstek/Yanıt Logları (Live Execution Audit Logs)** bulunmaktadır:

```
┌─────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                           burpinho Burp Extension                                           │
│                            (100% Pure Java — Zero External CLI Setup Required)                              │
│                                                                                                             │
│ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ... │
│ │ 1️⃣ PASSIVE AI│ │ 2️⃣ RECON    │ │ 3️⃣ IP SCANNER│ │ 4️⃣ VULN SCAN│ │ 5️⃣ XSS ANAL. │ │ 6️⃣ SQLI ANAL. │     │
│ │ Intercept &  │ │ Subdomains   │ │ CIDR / Range │ │ 50+ Vuln/API │ │ Canary/Poly  │ │ Error/Time   │     │
│ │ Real-time AI │ │ IP & Port Res│ │ PTR Hostname │ │ CVE Exposure │ │ Refl. Logs   │ │ DB Match Log │     │
│ └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘     │
│                                                                                                             │
│ ┌─────────────────────────────────────────────────────────────────────────────────────────────────────────┐ │
│ │                                  burpinho 100% Pure Java Core Engines                                   │ │
│ │   • Hiçbir harici tool, Go, Python veya .exe kurulumu gerekmez!                                         │ │
│ │   • Windows, macOS ve Linux üzerinde JAR yükle ve hemen çalıştır                                        │ │
│ │   • Canlı İstek/Yanıt Analiz Logları (Live Payload & Socket Audit Console)                               │ │
│ │   • (Opsiyonel: Sistemde Nuclei/Ffuf varsa otomatik hızlandırır)                                        │ │
│ └─────────────────────────────────────────────────────┬───────────────────────────────────────────────────┘ │
│                                                       │                                                     │
│                                                       ▼                                                     │
│ ┌─────────────────────────────────────────────────────────────────────────────────────────────────────────┐ │
│ │                               Local AI Engine (Ollama / OpenAI Compatible)                              │ │
│ │   • Zafiyet Yorumlama, PoC Üretimi, Executive Summary & Risk Skorlaması                                 │ │
│ └─────────────────────────────────────────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 🧰 9 Özel Bağımsız Modül Menüsü

### 1️⃣ Passive AI
* Burp Proxy / Repeater trafiğini arka planda anlık olarak inceleyen, hassas verileri (şifre, token, cookie) otomatik maskeleyen ve yerel LLM üzerinden risk analizi yapan motor.

### 2️⃣ Recon (Subdomain & IP)
* **Alt Alan Adı Keşfi:** HackerTarget API & 100+ kurumsal alt alan adı sözlüğü (`api`, `admin`, `dev`, `stage`, `vpn`, `sso`, `idp`, `keycloak`, `jenkins`, `gitlab`, `db` vb.).
* **IP & Port Çözümleme:** Keşfedilen her subdomain'in IP adreslerini, açık portlarını (`80, 443, 8080, 8443, 22, 3306...`), HTTP durum kodunu (`200, 301, 403`), Sayfa Başlığını ve Web Sunucusunu tablo halinde listeler.
* **WAF Tespiti:** Cloudflare, AWS WAF, Akamai, Imperva, F5 BIG-IP, Azure Front Door dahil 20+ WAF tespiti.
* **Teknoloji Tespiti:** WordPress, React, Next.js, Spring Boot, Django, Laravel dahil 40+ framework tespiti.
* **CSV Dışa Aktarma & Canlı Audit Logu.**

### 3️⃣ IP & Network Scanner
* **Girdi Formatları:** Tekil IP (`192.168.1.10`), Virgülle ayrılmış IP'ler, IP Aralığı (`192.168.1.1-50`), CIDR Subnet (`10.0.0.0/24`) veya Domain.
* **Reverse DNS (PTR):** Ağdaki IP'lerin ters DNS sorguları ile sunucu isimlerini keşfeder.
* **Port Profilleri:** En Kritik 25 Port, Web Portları (80, 443, 8080, 8443...), Top 100 Port, Veritabanı Portları veya Özel Port Listesi.
* **HTTP Servis Tespiti:** Açık portlarda başlık (`<title>`) ve HTTP `Server` banner çekme.
* **Canlı Soket Logu & Canlı Tablo Güncellemesi.**

### 4️⃣ Vulnerability Scanner (Nuclei & CVE Exposure)
* **50+ Hassas Dosya ve API İfşası:**
  - `/.env`, `/.git/HEAD`, `/.git/config`, `/.svn/entries`, `/robots.txt`, `/.DS_Store`, `/phpinfo.php`, `/web.config`, `/.bash_history`
  - `/swagger.json`, `/openapi.json`, `/api-docs`, `/swagger-ui.html`, `/docs`, `/graphql`
  - `/actuator`, `/actuator/health`, `/actuator/env`, `/actuator/beans`, `/actuator/metrics`
  - `/backup.sql`, `/dump.sql`, `/db.sql`, `/backup.zip`, `/site.zip`
* **CORS & Güvenlik Başlıkları:** `Origin: evil-attacker.com` kontrolü, eksik CSP/HSTS/X-Frame-Options tespiti.
* **Zafiyet Seviyesi (Critical/High/Medium/Low) ve Detay Tablosu.**

### 5️⃣ XSS Analyzer
* **Gelişmiş Parametre Analizi:** URL parametrelerini otomatik ayrıştırır.
* **Payload Seçenekleri:** Auto Polyglot & Canary Reflection, `<svg/onload=alert(1)>`, `"><script>alert(1)</script>`, `javascript:alert(1)` ve Özel Canary Payload'ları.
* **Canlı İstek & Yansıma Logu:** Enjekte edilen istek ve yanıttaki ham yansımayı anlık gösterir.

### 6️⃣ SQLi Analyzer
* **Teknikler:** Error-based, Boolean-based Quote Break, Time-based Blind Delay (`SLEEP / pg_sleep / WAITFOR`).
* **Veritabanı Hata İmzaları:** MySQL, PostgreSQL, Oracle, MSSQL, SQLite hata eşleştirmesi.
* **Canlı Gecikme & Yanıt Denetim Logu.**

### 7️⃣ Path Fuzzer
* **URL/FUZZ Desteği:** `https://example.com/FUZZ` veya temel URL.
* **Hazır Sözlükler:** Common Web Paths, Admin/Login/Portals, API/Microservices, Sensitive Backups veya Özel Sözlük.
* **HTTP Durum Kodu Filtresi:** `200, 201, 301, 302, 307, 401, 403, 500`.

### 8️⃣ Exploit & PoC Advisor
* **Exploit Arama:** CVE veya teknoloji adı ile exploit sorgulama.
* **AI PoC Üretici:** Hedef zafiyete özel Python ve cURL doğrulama betikleri üretimi ve tek tıkla kopyalama.

### 9️⃣ Report Generator
* Tüm modüllerin bulgularını (Pasif AI, Recon, IP Scan, Zafiyetler, XSS, SQLi, Fuzzing) birleştiren modern **Dark Theme HTML** raporu oluşturur ve tarayıcıda otomatik açar.

---

## 🚀 Hızlı Başlangıç / Quick Start

### 1. Eklentiyi Burp Suite'e Ekleyin
1. **[burpinho-3.2.0.jar](https://github.com/batuhansnl/burpinho/raw/main/releases/burpinho-3.2.0.jar)** dosyasını indirin.
2. Burp Suite'i açın: **Extensions** → **Installed** → **Add**
3. **Extension type:** `Java` seçin.
4. **Extension file:** İndirdiğiniz `burpinho-3.2.0.jar` dosyasını seçip **Next** deyin.
5. Üst menüde **burpinho** sekmesi belirecektir!

### 2. Sağ Tık (Context Menu) Entegrasyonu
Burp Proxy, Repeater veya Target Sitemap'teki herhangi bir isteğe sağ tıklayarak:
* `⚡ Analyze Request (AI)`
* `🔍 Send Host to Recon (Subdomain & IP)`
* `🌐 Send Host to IP & Network Scanner`
* `🛡️ Send URL to Vulnerability Scanner`
* `🧪 Send URL to XSS Analyzer`
* `💉 Send URL to SQLi Analyzer`
* `🎯 Send Base URL to Path Fuzzer`
* `💥 Send URL to Exploit & PoC Generator`
seçenekleriyle anında ilgili sekmeye hedefi aktarabilirsiniz.

---

## ⚙️ Yerel LLM Ayarları (İsteğe Bağlı)

Eklenti içindeki **Settings** butonundan yerel yapay zeka modelinizi bağlayabilirsiniz:

* **Ollama (Default):**
  - URL: `http://localhost:11434/api/generate`
  - Model: `llama3.2`, `qwen2.5-coder`, `mistral` vb.
* **OpenAI-Compatible (LocalAI / vLLM / LM Studio / Şirket İçi Sunucu):**
  - URL: `http://localhost:1234/v1` veya `http://internal-ai-server:8000/v1`
  - API Key: İsteğe bağlı
  - Model: `deepseek-coder`, `qwen`, `codellama` vb.

---

## 🛡️ Gizlilik ve Güvenlik
* **%100 Yerel İstemci:** Tüm soket, DNS, HTTP taramaları doğrudan sizin bilgisayarınızdan Burp üzerinden yapılır.
* **Sıfır Telemetri:** Hiçbir tarama veya istek verisi dış sunuculara iletilmez.

---

**Geliştirici:** Batuhan Şenel  
**GitHub:** [github.com/batuhansnl/burpinho](https://github.com/batuhansnl/burpinho)