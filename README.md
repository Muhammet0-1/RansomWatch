# RansomWatch

[![CI](https://github.com/Muhammet0-1/RansomWatch/actions/workflows/ci.yml/badge.svg)](https://github.com/Muhammet0-1/RansomWatch/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/Python-3.10--3.13-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

RansomWatch, açıkça seçilmiş yerel bir dizindeki deterministik **canary dosyalarının**
bütünlüğünü izleyen savunma amaçlı bir uç nokta güvenliği laboratuvarıdır. Değiştirilen,
silinen veya güvenli olmayan bir duruma getirilen canary dosyalarını metin ya da JSONL alarmı
olarak bildirir.

> [!IMPORTANT]
> RansomWatch bir ransomware önleme, süreç ilişkilendirme veya dosya kurtarma ürünü değildir.
> Canary değişikliği güçlü bir inceleme sinyalidir; tek başına zararlı yazılım bulunduğunu
> kanıtlamaz. Katmanlı uç nokta koruması ve test edilmiş yedeklerin yerini almaz.

## Neden bu tasarım?

İlk PoC, kullanıcının ana dizinine tek bir yem dosya bırakıyor, dosya yolunu alt dizeyle
eşleştiriyor, çalışan süreçleri listeliyor ve alarmda uygulamayı aniden sonlandırıyordu. Bu sürüm
aynı savunma fikrini güvenli ve test edilebilir bir mühendislik projesine dönüştürür:

- izlenecek dizin zorunlu ve açıkça belirtilir;
- dizin özel, sahibi kullanıcı olan ve grup/dünya tarafından yazılamayan bir konum olmalıdır;
- dosya işlemleri sabitlenmiş dizin descriptor'ı üzerinden yapılır;
- canary dosyaları `0600` izinleriyle ve üzerine yazmadan oluşturulur;
- symlink, hard-link, özel dosya, farklı sahip ve geniş izin durumları reddedilir;
- canary yolları tam eşleşmeyle değerlendirilir;
- Watchdog olaylarına ek olarak periyodik bütünlük denetimi yapılır;
- süreç listeleme, süreç öldürme, karantina ve ağ iletişimi yoktur;
- alarm kalıcılığı kullanıcıya bırakılır; araç varsayılan olarak yalnızca standart çıktıya yazar.

## Özellikler

- Deterministik ve hassas veri içermeyen 1-32 canary dosyası
- Değiştirme, silme, taşıma ve güvenli olmayan metadata tespiti
- Kaçırılmış dosya sistemi olayları için periyodik bütünlük denetimi
- Monotonic saate dayalı, bellek açısından sınırlı alarm cooldown'u
- İnsan tarafından okunabilir metin veya makine tarafından işlenebilir JSONL
- İzole geçici dizinde çalışan, zararsız `self-test`
- Python 3.10-3.13 CI matrisi, Ruff, strict mypy, pytest ve wheel/sdist üretimi

## Platform ve güvenlik gereksinimleri

RansomWatch 0.2, güvenli `dir_fd`, `O_DIRECTORY` ve `O_NOFOLLOW` işlemlerini sağlayan POSIX
sistemlerini hedefler. Linux üzerinde geliştirilmiştir. Root olarak çalıştırmayın.

İzleme için ayrı ve özel bir dizin oluşturun:

```bash
mkdir -m 700 "$HOME/ransomwatch-lab"
```

Gerçek kullanıcı belgelerinin bulunduğu ana dizini doğrudan izlemek önerilmez.

## Kurulum

```bash
git clone https://github.com/Muhammet0-1/RansomWatch.git
cd RansomWatch

python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
```

Geliştirme araçlarıyla kurulum:

```bash
python -m pip install -e '.[dev]'
```

## Hızlı başlangıç

Canary dosyalarını oluşturun veya mevcut olanları doğrulayın:

```bash
ransomwatch deploy --watch-dir "$HOME/ransomwatch-lab"
```

Mevcut bütünlük durumunu ağ veya canlı izleme olmadan kontrol edin:

```bash
ransomwatch status --watch-dir "$HOME/ransomwatch-lab"
```

Canlı izlemeyi başlatın:

```bash
ransomwatch watch --watch-dir "$HOME/ransomwatch-lab"
```

Başka bir terminalde yalnızca kendi laboratuvar canary dosyanızı değiştirerek alarmı
gözlemleyebilirsiniz. Yeniden dağıtım mevcut ve değiştirilmiş bir dosyanın üzerine yazmaz;
önce laboratuvar dizinini inceleyip bilinçli biçimde temizlemeniz gerekir.

## Zararsız self-test

Gerçek izleme dizinine dokunmadan tüm canary/detector/rapor hattını doğrulayın:

```bash
ransomwatch self-test
ransomwatch self-test --format jsonl
```

Komut yalnızca yeni bir sistem geçici dizini oluşturur, içinde bir canary değişikliği üretir ve
dizin otomatik silinmeden önce beklenen alarmı gösterir.

## JSONL çıktısı

```bash
ransomwatch watch \
  --watch-dir "$HOME/ransomwatch-lab" \
  --format jsonl \
  > ransomwatch-alerts.jsonl
```

Örnek şema:

```json
{
  "canary": ".ransomwatch-canary-01.txt",
  "detail": "content differs from the deterministic baseline",
  "detector": "canary_integrity",
  "event_type": "modified",
  "observed_at": "2026-08-20T12:00:00+00:00",
  "schema_version": 1,
  "severity": "high",
  "state": "modified"
}
```

Çıktı dosyası güvenliğinin shell ve işletim sistemi sorumluluğunda olduğunu unutmayın.
Örneğin kayıttan önce `umask 077` kullanabilirsiniz.

## Komutlar

```text
ransomwatch deploy    Canary dosyalarını oluştur veya doğrula
ransomwatch status    Bütünlüğü tek sefer kontrol et
ransomwatch watch     Watchdog ve periyodik audit ile izle
ransomwatch self-test Geçici dizinde zararsız uçtan uca test çalıştır
```

Ortak seçenekler:

- `--watch-dir PATH`: mevcut, özel ve kullanıcıya ait laboratuvar dizini (zorunlu)
- `--count N`: canary sayısı, `1-32` (varsayılan `3`)
- `--format text|jsonl`: durum/alarm biçimi
- `--cooldown SECONDS`: yinelenen alarm aralığı (varsayılan `10`)
- `--audit-interval SECONDS`: periyodik bütünlük kontrolü (varsayılan `2`)

Eski giriş noktası paket kurulduktan sonra çalışmaya devam eder:

```bash
python sentinel.py --help
```

## Çıkış kodları

| Kod | Anlam |
| ---: | --- |
| `0` | Komut başarıyla tamamlandı veya tüm canary dosyaları sağlıklı |
| `1` | Bütünlük kaybı ya da çalışma zamanı/raporlama hatası |
| `2` | Güvenli olmayan veya geçersiz yapılandırma |
| `130` | Klavye kesmesi |

## Mimari

```text
src/ransomwatch/
├── canary.py      # descriptor-anchored oluşturma ve doğrulama
├── cli.py         # komutlar, çıkış kodları ve sinyal yaşam döngüsü
├── config.py      # sınırlar ve güvenli dizin doğrulaması
├── detector.py    # olay korelasyonu ve cooldown
├── models.py      # immutable durum, olay ve alarm modelleri
├── reporting.py   # metin/JSONL stdout raporlama
└── service.py     # Watchdog adaptörü ve periyodik audit döngüsü
```

## Tehdit modeli ve sınırlamalar

RansomWatch, saldırganın henüz canary dosyalarını keşfedip özel olarak atlamadığı varsayımıyla
bir **erken uyarı sinyali** üretir. Şunları yapmaz:

- dosya olayını belirli bir PID veya kullanıcıyla ilişkilendirme;
- ransomware ailesi veya niyeti belirleme;
- şifrelemeyi durdurma, süreç öldürme veya sistemi kilitleme;
- silinen/şifrelenen dosyaları kurtarma;
- kernel seviyesinde denetim veya bütünlük garantisi;
- ağ paylaşımı, Windows veya macOS için eşdeğer güvenlik garantisi.

Canary adı tahmin edilebilir olduğu için hedefli bir saldırgan onu atlayabilir. Gerçek ortamda bu
sinyali EDR, merkezi loglama, en az ayrıcalık, immutable/offline yedekler ve geri yükleme
tatbikatlarıyla birlikte değerlendirin.

## Geliştirme ve doğrulama

```bash
ruff check .
mypy
pytest
python -m build
```

Testler gerçek malware, ağ isteği, süreç öldürme veya kullanıcı dizini üzerinde değişiklik
oluşturmaz. Dosya sistemi senaryoları özel geçici dizinlerde çalışır.

## Etik kullanım

Yalnızca sahibi olduğunuz veya yönetme/izleme yetkisine sahip olduğunuz sistemlerde kullanın.
İzleme politikanızı, kullanıcı bildirimlerini ve yerel mevzuatı dikkate alın. Bu depo gerçek
malware örneği içermez ve saldırı otomasyonu sağlamaz.

## Katkı ve güvenlik

- Katkı süreci: [CONTRIBUTING.md](CONTRIBUTING.md)
- Güvenlik politikası: [SECURITY.md](SECURITY.md)
- Sürüm notları: [CHANGELOG.md](CHANGELOG.md)
- Lisans: [MIT](LICENSE)
