# RextroDeobf

Java `.jar` dosyalarını otomatik olarak decompile edip deobfuscate eden, bağımlılıksız (sadece Node.js) bir web aracı. JAR'ı tarayıcıya sürükle, temizlenmiş kaynak kodu sayfada gör.

## Özellikler

- CFR ile decompile (`lib/cfr.jar`)
- Şifreli string havuzunu çözme, junk kod temizleme, sabit katlama
- Gizlenmiş `invokedynamic` çağrılarını geri kurma
- Control-flow flattening (state-machine döngüleri) çözme, `$SwitchMap$` enum switch'lerini geri getirme
- Sınıf / alan / metot yeniden adlandırma, yerel tip çıkarımı
- ProGuard, ZKM ve benzeri obfuscator'lar için özel temizleyiciler (`tools/skidclean`)

## Gereksinimler

- Node.js (bağımlılık yok, `npm install` gerekmez)
- Java (JDK/JRE) — CFR ve yardımcı araçlar için
- Python 3 — `engine/` içindeki deobf hattı için

## Çalıştırma

```bash
node server.js
```

Sonra tarayıcıda <http://localhost:3000> adresini aç. Port için `PORT` ortam değişkeni kullanılabilir. Linux'ta `./start.sh` de sunucuyu başlatıp sayfayı açar.

- Maksimum yükleme: 200 MB
- İşler `work/` klasöründe tutulur ve 1 saat sonra silinir

## Komut satırından

```bash
python engine/pipeline.py --src <decompile_edilmis_java_klasoru> --out <cikti> [--jar orijinal.jar] [--no-rename]
```

## Yapı

| Yol | Açıklama |
|---|---|
| `server.js` | HTTP sunucusu, decompile + deobf orkestrasyonu |
| `public/` | Web arayüzü |
| `engine/` | Python deobf hattı (string, flow, alan/metot adlandırma) |
| `tools/skidclean/` | Java tabanlı obfuscator temizleyicileri |
| `lib/` | CFR ve ASM jar'ları |

## Uyarı

Sadece kendi yazdığın veya analiz etme iznin olan yazılımlar üzerinde kullan.
