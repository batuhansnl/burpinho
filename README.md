# 🧙‍♂️ burpinho

<div align="center">

![burpinho Logo](https://img.shields.io/badge/burpinho-AI%20Security-blue?style=for-the-badge)
[![Burp Suite](https://img.shields.io/badge/Burp_Suite-Extension-orange?style=for-the-badge&logo=burpsuite)](https://portswigger.net/burp)
[![Java](https://img.shields.io/badge/Java-17%2F21-yellow?style=for-the-badge&logo=openjdk)](https://www.java.com/)
[![GitHub Release](https://img.shields.io/github/v/release/batuhansnl/burpinho?style=for-the-badge&color=green)](https://github.com/batuhansnl/burpinho/releases)

### 🔗 🧠 🔒

**AI-Powered Passive Vulnerability Analysis for Burp Suite**  
*(with Local & OpenAI-Compatible LLM Support)*

[⬇️ **Download Latest JAR**](https://github.com/batuhansnl/burpinho/releases/latest/download/silentchain-community-edition-1.3.0.jar) • [🚀 Quick Start](#-quick-start) • [🔧 Configuration](#-configuration)

</div>

---

## 📥 İndirme / Download JAR

Hazır derlenmiş eklenti dosyasını doğrudan indirip Burp Suite'e ekleyebilirsiniz:

> 📦 **[burpinho v1.3.0 JAR İndir (GitHub Releases)](https://github.com/batuhansnl/burpinho/releases/latest/download/silentchain-community-edition-1.3.0.jar)**
> 
> *Alternatif yerel derleme yolu:* `build/libs/silentchain-community-edition-1.3.0.jar`

---

## 🌟 Genel Bakış / Overview

**burpinho**, web uygulaması güvenlik testlerinde yapay zekanın gücünü Burp Suite'e taşıyan akıllı bir eklentidir. HTTP trafiğini pasif olarak analiz ederek OWASP Top 10 zafiyetlerini, güvenlik yapılandırma hatalarını ve olası saldırı vektörlerini tespit eder.

### 💡 burpinho ile Neler Değişti?
- 🏠 **Lokal & Şirket İçi LLM Desteği (OpenAI-Compatible):** vLLM, TGI, Ollama, LocalAI veya şirket içi barındırılan büyük modeller (örn. `Qwen3.5-122B-A10B`) için API Key zorunluluğu olmaksızın tam uyumluluk.
- 🔌 **Esnek Endpoint Bağlantısı:** Standart `/v1/models` ve `/v1/chat/completions` uç noktaları üzerinden kesintisiz iletişim.
- 🔒 **Gelişmiş TLS & Network Yönetimi:** Plain HTTP (`http://`) yerel ağ adreslerinde gereksiz TLS doğrulamalarını atlayarak DNS/bağlantı hatalarını önler.
- 🛡️ **Veri Sanitizasyonu (DataSanitizer):** İstek ve yanıtlardaki hassas verileri (API anahtarları, token'lar, şifreler) modele iletmeden önce otomatik maskeleme.

---

## ✨ Desteklenen AI Sağlayıcıları

- **OpenAI (Local & Cloud):** Şirket içi yerel sunucular (`http://<ip>:<port>/v1`) veya resmi OpenAI API (`https://api.openai.com/v1`).
- **Ollama:** `http://localhost:11434` üzerinden yerel modeller.
- **Burp AI:** Burp Suite Professional dahili AI servisi.
- **Claude (Anthropic)**
- **Google Gemini**
- **Azure OpenAI / Foundry**

---

## 🚀 Hızlı Başlangıç / Quick Start

### 1. Eklentiyi İndirin ve Yükleyin
1. **[JAR dosyasını indirin](https://github.com/batuhansnl/burpinho/releases/latest/download/silentchain-community-edition-1.3.0.jar)**.
2. Burp Suite'i açın: **Extensions** → **Installed** → **Add**
3. **Extension Type:** `Java` seçin.
4. İndirdiğiniz `.jar` dosyasını seçip **Next** diyerek kurulumu tamamlayın.

### 2. Şirket İçi / Yerel LLM Sunucunuzu Bağlayın
1. Burp içinde **SILENTCHAIN / burpinho** sekmesine gelin → **⚙ Settings**
2. **AI Provider:** `OpenAI` seçin.
3. **API URL:** `http://<SUNUCU_IP>:<PORT>/v1` (örn: `http://192.168.1.50:8000/v1`)
4. **API Key:** Sunucunuz istemiyorsa boş bırakabilirsiniz (veya `sk-local`).
5. **Model:** Sunucudaki model adını girin (örn: `Qwen3.5-122B-A10B`).
6. **Test Connection** butonuna basarak bağlantıyı doğrulayın.

---

## 🛠️ Kaynak Koddan Derleme (Build from Source)

Projeyi sıfırdan derlemek isterseniz:

```bash
# Repoyu klonlayın
git clone https://github.com/batuhansnl/burpinho.git
cd burpinho

# Gradle ile derleyin
gradle shadowJar
```

Derlenen dosya `build/libs/silentchain-community-edition-1.3.0.jar` dizininde oluşacaktır.

---

## 🛡️ Gizlilik ve Güvenlik (DataSanitizer)

- Varsayılan olarak etkindir.
- Cloud veya yerel LLM'e gönderilen isteklerdeki hassas API anahtarlarını, oturum cookie'lerini, Bearer token'ları ve e-posta adreslerini `[REDACTED_*]` olarak maskeler.
- İsteğe göre **Settings** ekranından kapatılabilir veya özelleştirilebilir.

---

## 📄 Lisans

Bu proje topluluk kullanımı için geliştirilmiştir. Orijinal altyapı SILENTCHAIN CE üzerine kurulmuştur.