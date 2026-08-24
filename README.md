<div align="center">
  <h1>🕵️‍♂️ NestTrace v5.1</h1>
  <p><strong>Field-Hardened Enterprise OSINT Framework</strong></p>
  
  [![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
  [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
  [![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://GitHub.com/Saykopatkhan/nesttrace/graphs/commit-activity)
  [![OSINT](https://img.shields.io/badge/Category-OSINT-red.svg)]()
</div>

---

## 📖 Proje Hakkında (Introduction)

**NestTrace**, hedef profillerin dijital ayak izlerini sürmek ve derinlemesine istihbarat toplamak için geliştirilmiş **yeni nesil, profesyonel bir OSINT (Açık Kaynak İstihbaratı) aracıdır.** 

Sosyal medya platformlarının giderek zorlaşan anti-bot sistemlerini (Cloudflare, CAPTCHA, davranışsal analiz) atlatmak üzere tasarlanmıştır. Hedefin farklı platformlardaki aynı biyografi, kullanıcı adı veya avatarlarını tespit eden gelişmiş bir **Korelasyon Motoru**'na (Correlation Engine) sahiptir. Bir hedefin "yuvasını" (nest) bulmak için dijital kırıntıları (trace) takip eder.

## ✨ Öne Çıkan Özellikler

- 🌐 **Geniş Platform Desteği:** TikTok, Instagram, Twitter/X, YouTube, Facebook, LinkedIn, Reddit, GitHub, Wayback Machine.
- 🥷 **Gelişmiş Stealth (Gizlilik):** 
  - TLS parmak izi gizleme (`curl_cffi`).
  - Playwright üzerinden JS enjeksiyonları ile Webdriver tespiti engelleme.
  - İnsan benzeri fare hareketleri ve sayfa kaydırma (scrolling) simülasyonları.
- 🧩 **CAPTCHA Atlatma Modu:** Tespit durumunda aracı duraklatarak manuel çözüm imkanı tanır (`--solve-captcha`).
- 🔗 **Yapay Korelasyon:** Elde edilen verileri çaprazlayarak (aynı bio, aynı isim) hedefin diğer platformlardaki gizli hesaplarını açığa çıkarır.
- 📊 **Çoklu Çıktı (Raporlama):** Analiz sonuçlarını **JSON**, **HTML** veya **Markdown** formatında, göz alıcı bir şekilde raporlar.
- 🌍 **Proxy Desteği:** Hem CLI üzerinden hem de `.txt` dosyasından Residential/Datacenter proxy desteği sağlar.
- 📱 **Çapraz Platform (Termux & Windows):** Android (Termux) ortamını otomatik algılayıp yerel Chromium çalıştırabilme özelliği ve Windows kullanıcıları için tek tıkla `.exe` oluşturan yapım betiği (`build_exe.bat`) barındırır.

## ⚙️ Kurulum (Installation)

Sisteminize kurmak için aşağıdaki adımları takip edin:

```bash
git clone https://github.com/Saykopatkhan/nesttrace.git
cd nesttrace
pip install -r requirements.txt
python -m playwright install chromium
```

**📱 Termux (Android) Kullanıcıları İçin Ek Adım:**
Termux kullanıyorsanız Playwright tarayıcıları desteklemediği için sistem Chromium'unu kurmanız gerekir:
```bash
pkg install chromium
```
Araç Termux ortamında olduğunuzu otomatik algılayacak ve yerel Chromium'u kullanacaktır.

## 🚀 Kullanım (Usage)

Terminalden `nesttrace.py` dosyasını çalıştırarak hedef analizinizi başlatabilirsiniz:

**Temel Kullanım (Headless - Arka planda çalışır):**
```bash
python nesttrace.py saykopatkhan
```

**Görsel Arayüz Modu ve CAPTCHA Çözümü:**
*(Tarayıcı ekranda açılır, CAPTCHA çıkarsa sizden çözmenizi bekler)*
```bash
python nesttrace.py saykopatkhan --headed --solve-captcha
```

**Proxy ile Kullanım:**
```bash
python nesttrace.py saykopatkhan --proxy http://user:pass@host:port
# veya bir listeden okutmak için:
python nesttrace.py saykopatkhan --proxy-file proxies.txt
```

**Sadece Belirli Formatlarda Çıktı Alma:**
```bash
python nesttrace.py saykopatkhan --output html md
```

**Windows İçin Tek Tıkla .exe Oluşturma:**
Projeyi bir Windows bilgisayara indirdiğinizde, içindeki `build_exe.bat` dosyasına çift tıklayarak sistemi otomatik olarak kurabilir ve kendinize tek tıklamayla çalışabilen bir `NestTrace.exe` (dist/ klasörü içinde) oluşturabilirsiniz.

---

> [!WARNING]  
> ## ⚖️ Yasal Uyarı (Legal Disclaimer)
> **Bu araç yalnızca eğitim amaçlı, siber güvenlik farkındalığı ve yasal OSINT (Açık Kaynak İstihbaratı) araştırmaları için geliştirilmiştir.**
> Bu aracın kullanımından doğabilecek her türlü kötüye kullanım, veri ihlali veya zarardan yazar sorumlu tutulamaz. Hedef platformlardan otomatik veri çekmek (scraping), ilgili platformların *Kullanım Şartları'nı (Terms of Service)* ihlal edebilir. Aracı kullanırken yerel kanunlara ve etik kurallara uymak **tamamen son kullanıcının sorumluluğundadır.**

## 📄 Lisans (License)

Bu proje [**MIT Lisansı**](LICENSE) altında lisanslanmıştır. 
Özgürce kullanabilir, değiştirebilir ve dağıtabilirsiniz ancak yukarıdaki yasal sorumluluk reddi her zaman geçerlidir.
