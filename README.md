# 🧙‍♂️ burpinho

<div align="center">

![burpinho Logo](https://img.shields.io/badge/burpinho-Local%20AI%20Security-blue?style=for-the-badge)
[![Burp Suite](https://img.shields.io/badge/Burp_Suite-Extension-orange?style=for-the-badge&logo=burpsuite)](https://portswigger.net/burp)
[![Java](https://img.shields.io/badge/Java-17%2F21-yellow?style=for-the-badge&logo=openjdk)](https://www.java.com/)
[![Version](https://img.shields.io/badge/version-2.0.0-green?style=for-the-badge)](https://github.com/batuhansnl/burpinho)

### 🔗 🧠 🔒

**%100 Yerel, Gizli ve Özel AI Zafiyet Analiz Eklentisi (Burp Suite)**  
*(OpenAI-Compatible Local LLM & Ollama Odaklı)*

[⬇️ **Download burpinho v2.0.0 JAR**](https://github.com/batuhansnl/burpinho/raw/main/releases/burpinho-2.0.0.jar) • [🚀 Hızlı Başlangıç](#-hızlı-başlangıç--quick-start) • [⚙️ Ayarlar](#2-şirket-içi--yerel-llm-sunucunuzu-bağlayın)

</div>

---

## 📥 İndirme / Download JAR

En güncel derlenmiş **v2.0.0** eklenti dosyasını indirmek için aşağıdaki bağlantılardan birini kullanabilirsiniz:

* 📦 **[burpinho-2.0.0.jar İndir (GitHub Direct)](https://github.com/batuhansnl/burpinho/raw/main/releases/burpinho-2.0.0.jar)**
* 📦 **[burpinho-2.0.0.jar Dosyasına Git (GitHub View)](https://github.com/batuhansnl/burpinho/blob/main/releases/burpinho-2.0.0.jar)**
* 💻 *Lokal dosya yolu:* `releases/burpinho-2.0.0.jar`

---

## 🌟 burpinho v2.0.0 ile Neler Değişti?

**burpinho**, tamamen **şirket içi ve yerel yapay zeka modelleriyle** çalışmak üzere optimize edilmiş özel bir Burp Suite eklentisidir:

- 🏠 **Yalnızca Yerel & Özel LLM Odaklı:** Dış bulut bağımlılıkları sadeleştirildi; **OpenAI-Compatible Local (vLLM, TGI, LocalAI vb.)** ve **Ollama** tam optimize edildi.
- 🔓 **Dahili Sertifika & Self-Signed TLS Desteği:** Şirket içi `.local` veya internal CA sertifikalı HTTPS bağlantılarında yaşanan TLS engelleri tamamen kaldırıldı.
- 🔑 **Opsiyonel API Key:** Yerel modeller için token/key zorunluluğu kaldırıldı (sunucunuz token istiyorsa girebilirsiniz, istemiyorsa boş bırakılabilir).
- 🔄 **Çift Katmanlı Bağlantı Doğrulama:** Yerel sunucularda `/models` kapalı olsa bile `/chat/completions` üzerinden anında fallback ping testi yapar.
- 🛡️ **Gelişmiş DataSanitizer:** Analiz sırasında oturum token'larını, şifreleri, API key'leri otomatik maskeleyerek model context'ine güvenli şekilde iletir.

---

## ✨ Desteklenen Yerel AI Sağlayıcıları

1. **OpenAI Compatible (Local/Custom):**
   - Şirket içi LLM sunucuları (vLLM, TGI, FastChat, LM Studio, Ollama OpenAI endpoint'i vb.)
   - *Varsayılan Adres:* `http://localhost:8000/v1` veya `https://<sirket-llm-host>/v1`
2. **Ollama (Local):**
   - *Varsayılan Adres:* `http://localhost:11434`

---

## 🚀 Hızlı Başlangıç / Quick Start

### 1. Eklentiyi Burp Suite'e Ekleyin
1. **[burpinho-2.0.0.jar dosyasını indirin](https://raw.githubusercontent.com/batuhansnl/burpinho/main/releases/burpinho-2.0.0.jar)**.
2. Burp Suite'i açın: **Extensions** → **Installed** → **Add**
3. **Extension Type:** `Java`
4. İndirdiğiniz `burpinho-2.0.0.jar` dosyasını seçip **Next** deyin.

### 2. Şirket İçi / Yerel LLM Sunucunuzu Bağlayın
1. Burp menüsünde **burpinho** sekmesine gelin → **⚙ Settings**
2. **AI Provider:** `OpenAI Compatible (Local/Custom)` seçin.
3. **API URL:** `https://onemilliontoken.project-dev.serving.dkb-dc01-ai-application.adabank.local/v1` *(sonuna mutlaka `/v1` ekleyin)*
4. **API Key:** Sunucu token'ınızı yazın (veya gerekmiyorsa boş bırakın).
5. **Model:** Model adınızı yazın (örn: `Qwen3.5-122B-A10B` veya `/mnt/models`).
6. **Test Connection** butonuna basarak bağlantıyı onaylayın.

> 💡 **İpucu (Burp Upstream Proxy):** Şirket ortamında Burp Suite upstream proxy kullanıyorsa, **Settings -> Network -> Connections -> Upstream proxy servers** altında AI sunucunuzu (`*.adabank.local`) **Proxy host/port boş** olacak şekilde en üst sıraya eklemeyi unutmayın.

---

## 🛠️ Kaynak Koddan Derleme (Build from Source)

```bash
git clone https://github.com/batuhansnl/burpinho.git
cd burpinho

# Gradle ile derleyin
gradle shadowJar
```
Oluşan dosya: `build/libs/burpinho-2.0.0.jar`

---

## 📄 Lisans
Bu proje açık kaynak topluluk kullanımı için geliştirilmiştir.