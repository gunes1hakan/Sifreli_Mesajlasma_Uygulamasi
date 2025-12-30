# Wireshark Analizi

Bu proje TCP üzerinden metin tabanlı bir protokol kullanır.
Varsayılan sunucu portu: **6000** (Relay) veya **6001** (Decrypting/Ödev Modu).

## Localhost Trafiğini Yakalama (Windows)

Windows'ta standart Wireshark sürücüleri bazen `localhost` trafiğini (127.0.0.1) yakalayamaz. Bunun için **Npcap Loopback Adapter** gereklidir.

1. Wireshark kurulumu sırasında "Install Npcap" seçeneğini seçin.
2. "Support loopback traffic ('Npcap Loopback Adapter')" kutucuğunu işaretleyin.
3. Wireshark'ı açın ve arayüz listesinde **"Adapter for loopback traffic capture"** isimli adaptörü seçin.

## Filtreleme

Sadece sohbet trafiğini görmek için şu filtreyi kullanın:

```
tcp.port == 6000 || tcp.port == 6001
```

## Protokol Analizi

Mesajlar `|` (pipe) karakteri ile ayrılmış string formatındadır:

```
SENDER | ALGORITHM | ENCRYPTED(bool) | IV(Base64) | PAYLOAD(Base64) | TIMESTAMP
```

**Örnek (Plaintext):**
```
Alice|NONE|false||SGVsbG8=|1703456789000
```
*(Payload Base64 decode edilince "Hello" çıkar)*

**Örnek (AES-128 GCM):**
```
Alice|AES_GCM|true|...IV...|...EncryptedBytes...|1703456789000
```
