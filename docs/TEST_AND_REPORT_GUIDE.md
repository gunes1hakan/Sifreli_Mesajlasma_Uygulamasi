# PROJE TEST PROSEDÜRÜ VE DOĞRULAMA KILAVUZU

Bu doküman, projeyi Eclipse üzerinde çalıştırarak "AES–DES–RSA | Kütüphaneli/Kütüphanesiz | İstemci–Sunucu | Wireshark" ödev isterlerini doğrulamak için hazırlanmıştır.

---

## 1. HAZIRLIK VE ORTAM

### 1.1. Wireshark Kurulumu (Localhost Yakalama)
Standart Wireshark "localhost" trafiğini görmeyebilir.
1. **Wireshark**'ı açın.
2. Arayüz listesinde **"Adapter for loopback traffic capture"** seçeneğini bulun ve çift tıklayın.
   - *Eğer yoksa:* Wireshark'ı "Npcap" seçeneğiyle (ve "Loopback Support" kutucuğu işaretli) tekrar kurun.
3. Filtre çubuğuna şunu yazın ve Enter'a basın:
   ```
   tcp.port == 6000 || tcp.port == 6001
   ```

### 1.2. Eclipse Çalıştırma Düzeni
Testler sırasında ekranınızda şu 3 pencereyi yan yana getirin:
1. **Console** (Server çıktılarını takip etmek için)
2. **Secure Chat (Client A)**
3. **Wireshark**

---

## 2. ADIM ADIM TEST SENARYOLARI

### TEST 0: Duman Testi (Smoke Test)
Kodun temel fonksiyonlarının (Key üretimi, algoritma mantığı) çalıştığını doğrular.

1. **Eclipse**: `cryptoo.SmokeTest` sınıfına sağ tıklayın -> **Run As -> Java Application**.
2. **Beklenen Console Çıktısı**:
   ```
   === SMOKE TEST STARTED ===
   Check AES-128 Key Derivation... OK
   Check DES Key Derivation... OK
   ...
   [PASSED]
   ```
   *Eğer "FAILED" varsa devam etmeyin, koda dönün.*

---

### TEST 1: KÜTÜPHANELİ AES-GCM & SUNUCU DECRYPTION
**Amaç:** Sunucunun AES-128 GCM şifreli mesajı çözüp çözemediğini ve Client'ın doğru anahtar uzunluğunu kullandığını doğrulamak.

1. **Server Başlat**: `cryptoo.SecureChatServerDecrypting` -> **Run As Java Application**.
   - *Port varsayılan 6001 açılır.*
2. **Client A Başlat**: `cryptoo.SecureChatClient` -> **Run As Java Application**.
   - **Host**: 127.0.0.1
   - **Port**: `6001` (Dikkat: Decrypting server portu)
   - **Nick**: `Alice`
   - **Bağlan**'a basın.
   - *Check*: Server console: `[Server] Connected...`
3. **Session Key Gönderimi (Hazırlık)**:
   - Client A'da: **"Oturum Anahtarı (RSA)"** butonuna basın.
   - *Check*: Server console: `[Server] Captured Session Key from Alice (16 bytes)`
4. **Mesaj Gönderimi**:
   - **Algoritma**: `AES-GCM (PBKDF2 / Oturum)`
   - **Key Alanı**: `(BOŞ BIRAKIN)` -> *Boş olunca session key kullanılır.*
   - **Mesaj**: `Merhaba Dunya AES`
   - **Gönder (Şifreli)** butonuna basın.
5. **Doğrulama**:
   - **Server Console**:
     ```
     DECRYPTED MSG from Alice:
     Algo: AES_GCM
     Content: Merhaba Dunya AES
     ```
   - **Wireshark**:
     - Protokol satırında `AES_GCM` görünür.
     - Payload kısmı okunamaz (şifreli).
     - Paket Length: ~150-200 byte civarı (Wire format overhead dahil).

---

### TEST 2: KÜTÜPHANELİ DES & SUNUCU DECRYPTION
**Amaç:** Sunucunun DES şifreli mesajı çözdüğünü doğrulamak.

1. **Devam** (Server ve Client A açık).
2. **Session Key Yenileme (DES İçin)**:
   - *Not:* DES 8-byte key ister. AES key'i (16 byte) DES'e uymaz, ancak kodumuz `btnSendSessionKey` tıklandığında rastgele 32 byte gönderir. Server bunu map'e atar. `CryptoUtils.decrypt` metodumuz gelen byte array'i string'e çevirip kullanır mı?
   - *Kod Analizi:* `SecureChatServerDecrypting` -> DES decrypt için `new String(sessionKey)` yapar. `SecureChatClient` DES göndereceği zaman SessionKey'i B64 String olarak map'ten çeker ve `getBytes()` yapar.
   - *Pratik Test:* Tekrar "Oturum Anahtarı (RSA)" butonuna basın. (Server yeni key'i 'captures' eder).
3. **Mesaj Gönderimi**:
   - **Algoritma**: `DES (ECB)`
   - **Key Alanı**: `(BOŞ BIRAKIN)`
   - **Mesaj**: `Merhaba Dunya DES`
   - **Gönder (Şifreli)** butonuna basın.
4. **Doğrulama**:
   - **Server Console**: `DECRYPTED MSG from Alice ... Content: Merhaba Dunya DES`
   - **Wireshark**: `DES` etiketi görünür. Şifreli payload.

---

### TEST 3: RSA HYBRID (AES + RSA)
**Amaç:** "Hybrid" modun (RSA ile key dağıtımı + AES ile veri şifreleme) çalıştığını ve paket yapısını görmek.

1. **Hazırlık**: Client A (Alice) açık. Yeni bir Client B (`cryptoo_b.SecureChatClientNoEcho`) başlatın.
   - **Port**: `6001`
   - **Nick**: `Bob`
   - **Bağlan**.
2. **Client A (Alice) İşlemi**:
   - Bob bağlandığında Alice'in ekranına `[PUBKEY] stored for nick=Bob` düşmeli.
   - **Algoritma**: `AES-GCM + RSA` (veya `AES-GCM (BC) + RSA`)
   - **Key**: (Otomatik üretilir, girmeye gerek yok).
   - **Mesaj**: `Cok Gizli Hybrid Mesaj`
   - **Gönder (Şifreli)**.
3. **Doğrulama**:
   - **Client B (Bob)**: Ekranında `[Alice] Cok Gizli Hybrid Mesaj` görünür (Otomatik çözülür).
   - **Server Console**:
     - Eğer Server da "SERVER" nickiyle pubkey yayınladıysa ve sistemde ise server da çözebilir.
     - *Not:* Mevcut kodda Client A sadece "remotePublicKeys" listesindekilere wrapper key koyar. Server, Client'a "SERVER" olarak pubkey attıysa, Server da bu mesajı çözebilir.
     - *Check:* Server console'da Decrypted Msg görüyor musunuz? (Evet ise harika, Hayır ise sorun yok, Hybrid P2P odaklıdır).
   - **Wireshark (Kritik)**:
     - Bu paket ÇOK BÜYÜK olacaktır.
     - Çünkü içinde JSON payload var: `{"ct":"...", "keys":{"Bob":"<RSA_BLOCK>","SERVER":"<RSA_BLOCK>"}}`.
     - Her alıcı için 256 byte (2048 bit) RSA bloğu eklenir.

---

### TEST 4: MANUEL MODLAR (ÖDEV SPESİFİK)
**Amaç:** Manuel/Toy algoritmaların çalıştığını göstermek. Server bunları "Key bilmediği için" çözemez.

1. **Algoritma**: `AES-128 (MANUAL/SPN)`
2. **Key**: `secretkey` (Manual anahtar şart)
3. **Mesaj**: `Manuel Test`
4. **Gönder**.
5. **Doğrulama**:
   - **Client B (Bob)**: Eğer Bob aynı Key'i (`secretkey`) girmişse çözebilir mi?
     - *Hayır*, mevcut kodda manuel modda alıcı da manuel decrypt etmeli mi?
     - Sistem "SESSKEY" logiği haricinde otomatik decrypt için `resolveKeyForIncoming` kullanır.
     - Bob'un `Key` alanında da `secretkey` yazılıysa, mesaj geldiğinde otomatik çözülür.
   - **Server Console**:
     - `[Server] No session key for Alice...` veya şifreli halini basar (ÇÖZEMEZ).
     - *Bu beklenen bir durumdur.* Manuel mod uçtan uca gizlilik sağlar, server key'i bilmez.

---

## 3. RAPOR VERİ FORMU

Aşağıdaki tabloyu testler sırasında doldurun.

| Senaryo | Algoritma Seçimi | Veri Boyutu (Wireshark "Length") | Sunucu Mesajı Çözebildi mi? | Yorum (Hız/Güvenlik) |
| :--- | :--- | :--- | :--- | :--- |
| **1** | Plaintext (NONE) | ~100 bytes (Örnek) | EVET (Zaten açık) | Güvensiz, hızlı. |
| **2** | AES-GCM (Lib) | ? | EVET (Session Key ile) | Güvenli, standart, hızlı. |
| **3** | DES (Lib) | ? | EVET (Session Key ile) | Güvensiz (Kısa key), hızlı. |
| **4** | Hybrid (AES+RSA) | **Çok Yüksek** (Ör: 600+) | EVET | Güvenli + Key Paylaşımı. Paket boyutu RSA yüzünden büyük. |
| **5** | Manual SPN (AES) | ? | HAYIR | Öğretici amaçlı, server kör. |

### Karşılaştırma Soruları (Rapora Yazılacaklar)

1. **RSA Hybrid neden daha büyük paket boyutuna sahip?**
   *Cevap:* Çünkü her mesajın içinde, her alıcı için ayrı ayrı şifrelenmiş 2048-bit (256 byte) anahtar blokları taşınır.

2. **Server neden Manual Moddaki mesajı çözemedi?**
   *Cevap:* Manual modda anahtar ("secretkey") sadece Alice ve Bob arasında sözlü paylaşılmıştır. Server'da bu anahtar yoktur ve RSA/Session handshake kullanılmamıştır.

3. **AES-128 ile DES arasındaki temel fark nedir?**
   *Cevap:* AES 128-bit anahtar kullanır ve modern/güvenlidir. DES 56-bit (efektif) anahtar kullanır ve günümüzde brute-force ile saniyeler içinde kırılabilir.

---

## 4. RAPOR İÇİN EKRAN GÖRÜNTÜSÜ LİSTESİ

Raporunuza şu ekran görüntülerini eklemeniz önerilir:
1. **SmokeTest Başarılı**: Console çıktısı (`WARNING` olsa da `FAILED=0` olmalı).
2. **Server Decryption**: Server console'unda "DECRYPTED MSG... Content: Merhaba" yazan an.
3. **Wireshark Hybrid**: Protokol listesinde `AES_GCM_RSA` yazan, Length'i büyük olan paket detayı.
4. **Client UI**: Dropdown menü açıkken (Algoritma listesini göstermek için).
