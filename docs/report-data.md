# Rapor Verileri ve Senaryolar

Aşağıdaki senaryolar **SecureChatServerDecrypting** (Port 6001) üzerinde test edilmelidir.

## Senaryo 1: Plaintext
- **Mesaj:** "Merhaba Dunya"
- **Algoritma:** NONE
- **Beklenen:** Sunucu konsolunda "Merhaba Dunya" görünür.
- **Wireshark:** Payload Base64 decode edilince okunabilir.
- **Verimlilik:** En düşük boyut, güvenlik YOK.

## Senaryo 2: AES-128 GCM
- **Mesaj:** "Merhaba Dunya"
- **Algoritma:** AES_GCM (Parola: "1234")
- **Beklenen:** Sunucu parolanızı bilmediği için mesajı çözemez (Eğer manual parolayı sunucuya hardcode etmediyseniz).
- **Not:** Ödev server'ı sadece RSA Hybrid modunda veya SESSKEY modunda otomatik decrypt yapar. Manual modda key paylaşımı yoktur.
- **Wireshark:** Payload tamamen rastgele byte'lar görünür.

## Senaryo 3: RSA Hybrid (AES-128)
- **Adım 1:** Client "Oturum Anahtarı (RSA)" butonuna tıklar.
  - **Wireshark:** `SESSKEY` algoritmali mesaj gider. Payload boyutu büyüktür (256 byte / 2048 bit RSA şifreli session key).
  - **Server:** "Captured Session Key" logunu basar.
- **Adım 2:** Client şifreli mesaj atar ("Gizli Mesaj").
  - **Algoritma:** AES_GCM_RSA (veya AES_GCM + RSA UI seçimi)
  - **Wireshark:** `AES_GCM_RSA` etiketi görünür. Payload AES şifrelidir.
  - **Server:** Session key elinde olduğu için çözer ve "Gizli Mesaj" yazar.

## Senaryo 4: RSA Hybrid (DES)
- **Adım 1:** Oturum anahtarı gönderilir (DES için 8 byte key üretilir).
- **Adım 2:** Client şifreli mesaj atar.
  - **Algoritma:** DES_RSA
  - **Server:** DES ile çözer.

## Ödev Analiz Soruları İçin Notlar

1. **Neden RSA yavaştır / veri boyutu büyüktür?**
   - RSA asimetriktir ve büyük sayılarla (2048 bit) işlem yapar.
   - Sadece session key (küçük veri) göndermek için kullanılır.
   - Her mesajı RSA ile şifrelemek çok maliyetli olurdu.

2. **Hybrid sistemin avantajı nedir?**
   - Hız (AES/DES) ve Key Dağıtımı (RSA) avantajlarını birleştirir.
   - Session key her oturumda (veya her mesajda) yenilenebilir.

3. **AES vs DES**
   - DES anahtarı çok kısadır (56 bit efektif), brute-force ile kırılabilir.
   - AES-128 günümüz standardıdır ve güvenlidir.
