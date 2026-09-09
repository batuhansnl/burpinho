# 🧙‍♂️ burpinho v3.1.0 — 100% Self-Contained Local AI & Security Suite

<div align="center">

![burpinho Logo](https://img.shields.io/badge/burpinho-v3.1.0-blue?style=for-the-badge)
[![Burp Suite](https://img.shields.io/badge/Burp_Suite-Extension-orange?style=for-the-badge&logo=burpsuite)](https://portswigger.net/burp)
[![Java](https://img.shields.io/badge/Java-17%2F21-yellow?style=for-the-badge&logo=openjdk)](https://www.java.com/)
[![OS Support](https://img.shields.io/badge/OS-Windows%20%7C%20macOS%20%7C%20Linux-green?style=for-the-badge)](https://github.com/batuhansnl/burpinho)
[![Version](https://img.shields.io/badge/version-3.1.0-brightgreen?style=for-the-badge)](https://github.com/batuhansnl/burpinho)

### 🔗 🧠 ⚡ 🛡️

**%100 Dahili Saf Java Güvenlik Motorları (Recon, Vuln Scanner, XSS, SQLi, Fuzzing, WAF, Tech) + Yerel AI (Ollama / OpenAI Compatible)**  
*(Sıfır Dış Kurulum: Go, Python veya Harici Tool Gerektirmez — Şirket & Windows Bilgisayarları İçin %100 Uyumlu)*

[⬇️ **Download burpinho v3.1.0 JAR**](https://github.com/batuhansnl/burpinho/raw/main/releases/burpinho-3.1.0.jar) • [🚀 Hızlı Başlangıç](#-hızlı-başlangıç--quick-start) • [🧰 Modüller](#-modüller-ve-dahili-yetenekler) • [⚙️ Ayarlar](#-yerel-llm-ayarları)

</div>

---

## 📥 İndirme / Download JAR

En güncel tek parça **v3.1.0** eklenti dosyasını indirmek için:

* 📦 **[burpinho-3.1.0.jar İndir (GitHub Direct)](https://github.com/batuhansnl/burpinho/raw/main/releases/burpinho-3.1.0.jar)**
* 📦 **[burpinho-3.1.0.jar Dosyasına Git (GitHub View)](https://github.com/batuhansnl/burpinho/blob/main/releases/burpinho-3.1.0.jar)**
* 💻 *Lokal dosya yolu:* `releases/burpinho-3.1.0.jar` ve `/Users/batuhansenel/Downloads/burpinho-3.1.0.jar`

---

## 🌟 Neden burpinho v3.1.0?

Kısıtlı şirket ve banka bilgisayarlarında admin yetkisi olmaması, dışarıdan `go install`, `pip install`, `brew install` yapılamaması veya güvenlik politikaları sebebiyle harici binary (.exe) çalıştırılamaması problemlerini **%100 dahili Saf Java motorları** ile çözdük.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          burpinho Burp Extension                        │
│                 (100% Pure Java — Zero Setup Required)                  │
│                                                                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │ 1️⃣ PASSIVE AI│  │  2️⃣ RECON    │  │  3️⃣ SCANNER  │  │  4️⃣ REPORT   │ │
│  │ Intercept &  │  │ HackerTarget │  │ 50+ Vuln/API │  │ Standalone   │ │
│  │ Passive Scan │  │ DNS Wordlist │  │ XSS, SQLi    │  │ HTML Report  │ │
│  │ (Local LLM)  │  │ Socket Ports │  │ CORS, Fuzzer │  │ + AI Summary │ │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘ │
│         │                 │                 │                 │         │
│  ┌──────▼─────────────────▼─────────────────▼─────────────────▼───────┐ │
│  │                burpinho 100% Pure Java Core Engines                │ │
│  │   • Hiçbir harici tool, Go, Python veya .exe kurulumu gerekmez!    │ │
│  │   • Windows, macOS ve Linux üzerinde JAR yükle ve hemen çalıştır   │ │
│  │   • (Opsiyonel: Sistemde Nuclei/Ffuf varsa otomatik hızlandırır)   │ │
│  └────────────────────────────────┬───────────────────────────────────┘ │
│                                   │                                     │
│                                   ▼                                     │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │             Local AI Engine (Ollama / OpenAI Compatible)           │ │
│  │   • Zafiyet Yorumlama, PoC Üretimi, Executive Summary & Risk       │ │
│  └────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 🧰 Modüller ve Dahili Yetenekler

### 1️⃣ RECON Modülü (100% Dahili Keşif Motoru)
* **Pasif Subdomain Keşfi:** Dahili HackerTarget & Passive DNS sorgulama motoru.
* **Kurumsal Subdomain Wordlist:** En yaygın 100+ kritik subdomain (`api`, `admin`, `dev`, `stage`, `corp`, `vpn`, `sso`, `idp`, `keycloak`, `jenkins`, `gitlab`, `db`, `elastic`, `vault` vb.) için yüksek hızlı paralel DNS keşfi.
* **Çok Kanallı DNS Çözümleyici:** Subdomainlerin IP ve canlılık durumunu saniyeler içinde doğrulayan dahili Java DNS motoru.
* **Paralel Web Keşfi & HTTP Prober:** Port 80 ve 443 üzerinden başlık (`<title>`), HTTP kodu, Server ve Content-Length bilgilerini çeker.
* **Soket Port Tarayıcı:** En kritik 25 portu (`21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 1521, 3000, 3306, 3389, 5000, 5432, 6379, 8000, 8080, 8443, 8888, 9000, 9200, 27017`) doğrudan Java Socket ile tarar.
* **WAF İmzaları:** Cloudflare, AWS WAF, Akamai, Imperva, F5 BIG-IP, Sucuri, Fastly, Azure Front Door, Citrix NetScaler, Barracuda dahil 20+ WAF tespiti.
* **Teknoloji & Framework Tespiti:** WordPress, Drupal, React, Vue, Next.js, Spring Boot, Django, Laravel, ASP.NET, PHP, Nginx, Apache, IIS dahil 40+ teknoloji imzası.
* **Web Crawler / Spider:** HTML ve JS dosyalarından dahili Regex motoru ile form, link ve API endpoint çıkarıcı.

### 2️⃣ SCANNER Modülü (100% Dahili Zafiyet Tarayıcı)
* **50+ Hassas Dosya ve API İfşası (Dahili Nuclei Modeli):**
  - Yapılandırma & Gizli Dosyalar: `/.env`, `/.git/HEAD`, `/.git/config`, `/.svn/entries`, `/robots.txt`, `/.DS_Store`, `/phpinfo.php`, `/web.config`, `/.bash_history`
  - API Dokümantasyonu & Swagger: `/swagger.json`, `/openapi.json`, `/api-docs`, `/swagger-ui.html`, `/docs`, `/graphql`
  - Spring Boot Actuator: `/actuator`, `/actuator/health`, `/actuator/env`, `/actuator/beans`, `/actuator/mappings`, `/actuator/metrics`
  - Veritabanı Yedekleri: `/backup.sql`, `/dump.sql`, `/db.sql`, `/backup.zip`, `/site.zip`
* **Aktif XSS Analiz Motoru:** URL parametrelerine özel payload (`<svg/onload=1>`, `"onmouseover=1"`) enjekte ederek yanıttaki kodlanmamış yansımaları doğrular.
* **Aktif SQL Injection Analiz Motoru:** MySQL, PostgreSQL, Oracle, MSSQL, SQLite hata imzalarını tetikleyen özel karakter ve mantıksal sorgularla tarama yapar.
* **CORS & Güvenlik Başlıkları:** `Origin: evil-attacker.com` ve `Origin: null` istekleri göndererek kimlik doğrulamalı tehlikeli CORS açıklarını ve eksik CSP/HSTS başlıklarını raporlar.
* **Dizin & Path Fuzzer:** 50+ popüler yönetim ve servis yolunu paralel tarar.

### 3️⃣ EXPLOIT & POC Modülü
* Dahili PoC şablonları + Yerel AI üzerinden hedef zafiyete özel güvenli doğrulama payload'ları, cURL komutları ve Python betikleri üretimi.

### 4️⃣ REPORT Modülü
* Tüm bulguları (Recon, Zafiyetler, Pasif AI) tek bir **Dark Theme HTML** raporuna döker. AI bağlantısı varsa otomatik Executive Summary ve Risk Skorlaması ekler.

---

## 🚀 Hızlı Başlangıç / Quick Start

### 1. Eklentiyi Burp Suite'e Ekleyin
1. **[burpinho-3.1.0.jar](https://github.com/batuhansnl/burpinho/raw/main/releases/burpinho-3.1.0.jar)** dosyasını indirin.
2. Burp Suite'i açın: **Extensions** → **Installed** → **Add**
3. **Extension Type:** `Java`
4. `burpinho-3.1.0.jar` dosyasını seçip **Next** deyin.
5. **Kurulum bitti!** Hiçbir harici tool kurmadan hemen Recon ve Scanner sekmelerini kullanabilirsiniz.

### 2. Yerel LLM Ayarları (İsteğe Bağlı)
1. Burp menüsünde **burpinho** sekmesine gelin → **⚙ Settings**
2. **AI Provider:** `OpenAI Compatible (Local/Custom)` veya `Ollama (Local)` seçin.
3. **API URL:** Örnek: `http://localhost:11434` (Ollama) veya `http://localhost:8000/v1` (vLLM / LM Studio / Internal LLM).
4. **Test Connection** butonuna basarak bağlantıyı onaylayın.

---

## 🛠️ Kaynak Koddan Derleme (Build from Source)

```bash
git clone https://github.com/batuhansnl/burpinho.git
cd burpinho

# Gradle ile fat-jar derleyin
gradle shadowJar
```

Oluşan dosya: `build/libs/burpinho-3.1.0.jar`

---

## 📄 Lisans
Bu proje açık kaynak ve topluluk kullanımı için geliştirilmiştir.