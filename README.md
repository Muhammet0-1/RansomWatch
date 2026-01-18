# 🛡️ RansomWatch - Behavioral Ransomware Vaccine

![Python](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python)
![Security](https://img.shields.io/badge/Type-Endpoint%20Protection-green?style=for-the-badge)

**RansomWatch**, fidye yazılımlarının (Ransomware) dosya şifreleme faaliyetlerini gerçek zamanlı tespit etmek ve engellemek için geliştirilmiş davranışsal bir analiz aracıdır (Behavioral Analysis Tool).

Modern EDR (Endpoint Detection and Response) sistemlerinde kullanılan **"Honeypot / Canary Files"** tekniğini kullanır.

## ⚙️ Nasıl Çalışır?

1.  **Tuzaklama (Deployment):** Sistemdeki kritik dizinlere, kullanıcı dosyası gibi görünen sahte "yem dosyalar" (örn: `000_IMPORTANT_PASSWORD.docx`) yerleştirir. Fidye yazılımları genellikle alfabetik sırayla şifreleme yaptığı için bu dosyalara öncelik verirler.
2.  **İzleme (Monitoring):** `Watchdog` API kullanarak dosya sistemi olaylarını (File System Events) milisaniye bazında izler.
3.  **Tespit ve Müdahale (Detection & Kill):** Yem dosyalarda herhangi bir değişiklik (değiştirme, silme, şifreleme) tespit edildiğinde, işlemi gerçekleştiren süreci (Process) analiz eder ve tehdidi raporlar (PoC sürümünde simülasyon).

## 🚀 Kurulum ve Test

```bash
# Bağımlılıkları yükleyin
pip install watchdog psutil

# Korumayı başlatın
python sentinel.py

⚠️ Kullanım Alanı

Bu proje, fidye yazılımı davranışlarını analiz etmek ve savunma mekanizmalarını (Blue Team) geliştirmek amacıyla tasarlanmış bir Proof of Concept (PoC) çalışmasıdır.
