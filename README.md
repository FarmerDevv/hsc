# HSC - Hash Security Cracker

**Enterprise-Grade Cryptographic Hash Analysis & Recovery Tool**

HSC, profesyonel siber güvenlik uzmanları, adli bilişim araştırmacıları ve sistem denetçileri için geliştirilmiş güçlü bir hash kırma aracıdır. 20+ hash algoritması desteği, çok iş parçacıklı işleme ve modern GUI arayüzü ile kapsamlı hash analizi sunar.

---

## 🎯 Özellikler

### Core Functionality
- **20+ Hash Algoritması Desteği**: MD5, SHA ailesi, SHA3, BLAKE2, RIPEMD160, Whirlpool, NTLM ve daha fazlası
- **Çoklu İş Parçacığı**: Paralel işleme ile hızlandırılmış kırma operasyonları
- **İki Çalışma Modu**: CLI (komut satırı) ve GUI (grafik arayüz)
- **Detaylı Loglama**: Her deneme için opsiyonel verbose çıktı
- **Modern UI**: PyQt5 tabanlı dark theme arayüz
- **Gerçek Zamanlı İzleme**: İşlem ilerlemesi ve durum güncellemeleri

### Desteklenen Hash Algoritmaları
```
MD Family      : md4, md5
SHA-1          : sha1
SHA-2          : sha224, sha256, sha384, sha512
SHA-3          : sha3_224, sha3_256, sha3_384, sha3_512
SHAKE          : shake_128, shake_256
BLAKE          : blake2b, blake2s
Others         : ripemd160, whirlpool
Windows Auth   : ntlm, lm
```

---

## 📦 Kurulum

### Gereksinimler
- Python 3.7+
- pip paket yöneticisi

### Bağımlılıklar

**CLI Modu için (Zorunlu)**
```
pip install colorama rich
```

**GUI Modu için (Opsiyonel)**
```
pip install pyqt5
```

### Hızlı Kurulum
```
git clone https://github.com/yourusername/hsc.git
cd hsc
pip install -r requirements.txt
chmod +x hsc.py
```

---

## 🚀 Kullanım

### CLI Modu

#### Temel Kullanım
```
python hsc.py -H <hash_degeri> -w <wordlist_yolu> -t <hash_tipi>
```

#### Parametreler
- `-H, --hash`: Kırılacak hash değeri (zorunlu)
- `-w, --wordlist`: Wordlist dosya yolu (zorunlu)
- `-t, --type`: Hash algoritması türü (varsayılan: md5)
- `-v, --verbose`: Detaylı çıktı (her denemeyi gösterir)
- `--threads`: İş parçacığı sayısı (varsayılan: 4)
- `--gui`: GUI modunda başlat

#### Örnek Kullanımlar

**MD5 Hash Kırma**
```
python hsc.py -H 5d41402abc4b2a76b9719d911017c592 -w rockyou.txt -t md5
```

**SHA256 ile Verbose Mode**
```
python hsc.py -H e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 -w passwords.txt -t sha256 -v
```

**8 Thread ile Performans Artırma**
```
python hsc.py -H 098f6bcd4621d373cade4e832627b4f6 -w wordlist.txt -t md5 --threads 8
```

**NTLM Hash Kırma**
```
python hsc.py -H 8846f7eaee8fb117ad06bdd830b7586c -w wordlist.txt -t ntlm
```

### GUI Modu

#### Başlatma
```
python hsc.py --gui
```

veya

```
python hsc.py -gui
```

#### GUI Kullanımı

**Ana Ekran (HSC Tab)**
1. **Target Hash**: Kırılacak hash değerini girin
2. **Hash Type**: Dropdown menüden hash türünü seçin
3. **Wordlist**: Browse butonu ile wordlist dosyasını seçin
4. **Start Cracking**: İşlemi başlatın
5. **Output Log**: Gerçek zamanlı işlem loglarını görüntüleyin

**Özellikler**
- Dark theme modern arayüz
- Gerçek zamanlı log görüntüleme
- Renkli durum mesajları (INFO, WARN, ERROR)
- Start/Stop toggle özelliği
- İşlem süresi takibi
- Başarılı sonuçlarda otomatik vurgulama

---

## 📊 Çıktı Formatı

### Başarılı Kırma
```
==================================================
✅ HASH CRACKED!
Password: admin123
Time: 2.45 seconds
==================================================
```

### Başarısız Deneme
```
❌ Password not found.
```

### Verbose Mode Log Örneği
```
[14:23:45] [TRY] 'password' → 5f4dcc3b5aa765d61d8327deb882cf99
[14:23:45] [TRY] 'admin' → 21232f297a57a5a743894a0e4a801fc3
[14:23:46] [SUCCESS] HASH CRACKED!
```

---

## ⚙️ Yapılandırma

### Thread Sayısı Optimizasyonu
- CPU çekirdek sayınıza göre ayarlayın
- Önerilen: CPU çekirdek sayısı × 1-2
- Çok yüksek değerler sistem yavaşlamasına neden olabilir

### Wordlist Önerileri
- **rockyou.txt**: Genel amaçlı, 14M+ şifre
- **SecLists**: Kategorize edilmiş wordlist koleksiyonu
- Özel wordlist'ler için UTF-8 encoding kullanın

---

## 🔒 Güvenlik ve Etik Kullanım

**⚠️ UYARI**: Bu araç yalnızca yasal ve etik amaçlar için kullanılmalıdır.

### Yasal Kullanım Senaryoları
- Kendi sistemlerinizin güvenlik denetimi
- Adli bilişim araştırmaları (yetkili)
- Penetrasyon testi (yazılı izin ile)
- Eğitim ve araştırma (kontrollü ortamlarda)

### Yasadışı Kullanım
- İzinsiz sistemlere erişim **YASAK**
- Başkalarının verilerini çalmak **YASAK**
- Yetkisiz hash kırma işlemleri **YASAK**

**Kullanıcı sorumluluğundadır. Geliştirici kötüye kullanımdan sorumlu değildir.**

---

## 🛠️ Teknik Detaylar

### Mimari
- **Threading Model**: Python threading kütüphanesi ile paralel işleme
- **Hash Hesaplama**: Python hashlib (OpenSSL backend)
- **UI Framework**: PyQt5 (Fusion style)
- **CLI Framework**: Rich + Colorama

### Performans
- Thread başına bağımsız hash hesaplama
- Lock-free okuma işlemleri
- Event-driven sonlandırma mekanizması
- Bellek optimizasyonu ile büyük wordlist desteği


---

## 📝 Örnek Workflow

### Senaryo: Unutulan Admin Şifresi Kurtarma

**Adım 1: Hash Elde Etme**
```
# Linux shadow dosyasından
sudo cat /etc/shadow | grep username
```

**Adım 2: Hash Tipini Belirleme**
```
# $6$ = SHA-512
# $5$ = SHA-256
# $1$ = MD5
```

**Adım 3: HSC ile Kırma**
```
python hsc.py -H <hash> -w rockyou.txt -t sha512 -v --threads 8
```

**Adım 4: Sonuç Analizi**
```
[SUCCESS] Password: MySecurePass123
Time: 45.32 seconds
```

---

## 🐛 Sorun Giderme

### "Gerekli kütüphaneler eksik"
**Çözüm**: `pip install colorama rich` komutunu çalıştırın

### "GUI requires PyQt5"
**Çözüm**: `pip install pyqt5` komutunu çalıştırın

### "Wordlist not found"
**Çözüm**: Wordlist yolunun doğru olduğundan emin olun (tam/göreceli yol)

### Yavaş Performans
**Çözüm**: 
- Thread sayısını artırın: `--threads 8`
- Daha küçük wordlist kullanın
- SSD üzerinde çalışın

### GUI Açılmıyor
**Çözüm**:
- PyQt5 kurulu olduğundan emin olun
- Display server'ın çalıştığını kontrol edin (Linux)
- `python hsc.py --gui` komutuyla başlatın

---

---

## 📄 Lisans

Bu proje açık kaynak yazılımdır. Kendi sorumluluğunuzda kullanın.

---

## 👨‍💻 Katkıda Bulunma

Pull request'ler kabul edilmektedir. Büyük değişiklikler için önce issue açarak tartışın.

---


---

**⚡ HSC ile güvenli hash analizi yapın!**
