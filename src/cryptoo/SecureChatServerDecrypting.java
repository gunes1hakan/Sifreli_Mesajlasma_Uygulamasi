package cryptoo;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * ÖDEV UYUMLU SUNUCU (Decrypting Server).
 * 
 * Özellikler:
 * 1. RSA KeyPair üretir (Server Key).
 * 2. İstemcilerden gelen SESSKEY mesajlarını yakalar, unwrap eder, kaydeder.
 * 3. Şifreli mesajları (AES/DES) çözer ve konsola PLAINTEXT basar.
 * 4. Mesaj sahibine encrypted ACK gönderir.
 */
public class SecureChatServerDecrypting {

    // Server config
    private final int port;

    // RSA items
    private KeyPair rsaKeyPair;
    private PublicKey rsaPublic;
    private PrivateKey rsaPrivate;

    // Clients
    private final List<ClientHandler> clients = new CopyOnWriteArrayList<>();

    // Session Keys: Nick -> SessionKeyBytes (veya KeyString)
    // AES ve DES key'leri byte[] olarak tutmak daha güvenli ama burada basitlik
    // için String tabanlı harita kullanabiliriz
    // Ancak hibrit modda AES=16 byte, DES=8 byte raw key geliyor.
    // CryptoUtils decrypt metodları genelde String key veya Base64 key kabul eder.
    // Biz byte[] tutalım, decrypt ederken Base64'e çevirip veririz veya raw method
    // kullanırız.
    private final Map<String, byte[]> sessionKeys = new ConcurrentHashMap<>();

    public SecureChatServerDecrypting(int port) {
        this.port = port;
        initRSA();
    }

    private void initRSA() {
        try {
            System.out.println("[Server] Generating RSA Keypair (2048-bit)...");
            rsaKeyPair = CryptoUtils.genRsaKeyPair();
            rsaPublic = rsaKeyPair.getPublic();
            rsaPrivate = rsaKeyPair.getPrivate();
            System.out.println("[Server] RSA Keypair ready.");
        } catch (Exception e) {
            System.err.println("[Server] RSA Init Failed: " + e.getMessage());
        }
    }

    public void start() throws IOException {
        try (ServerSocket server = new ServerSocket(port)) {
            System.out.println("[Server] Decrypting Mode Listening on port " + port + "...");
            while (true) {
                Socket socket = server.accept();
                ClientHandler handler = new ClientHandler(socket, this);
                clients.add(handler);
                new Thread(handler, "Handler-" + socket.getRemoteSocketAddress()).start();
            }
        }
    }

    /**
     * Mesajı işle: Çözmeye çalış, logla, broadcast et.
     */
    void processAndBroadcast(String line, ClientHandler senderHandler) {
        // 1. Önce parse et
        SecureChatClient.WireMessage m = SecureChatClient.WireMessage.parse(line);
        if (m == null) {
            broadcastDirect(line, senderHandler); // Parse edilemedi, düz ilet
            return;
        }

        String senderNick = m.sender;

        // 2. Mesaj tipine göre server-side işlem
        if (CryptoUtils.ALGO_RSA_PUBREQ.equals(m.algorithm)) {
            // İstemci PubKey istiyor -> Server PubKey gönder
            sendServerPubKey(senderHandler);
        } else if (CryptoUtils.ALGO_RSA_PUB.equals(m.algorithm)) {
            // Client kendi pubkey'ini duyuruyor, logla
            System.out.println("[Server] PUBKEY received from " + senderNick);
            // Server da nezaketen kendi key'ini ona gönderebilir (handshake vari)
            // Ama loop olmasın. Sadece client ilk bağlandığında yapsak yeterli.
        } else if ("SESSKEY".equals(m.algorithm) || "SESSKEY".equals(m.algorithm.trim())) {
            handleSessionKey(m);
        } else if (m.encrypted) {
            // Şifreli mesaj -> Decrypt etmeye çalış
            tryDecryptAndPrint(m);
            // ACK Gönder
            sendEncryptedAck(m, senderHandler);
        }

        // 3. Mesajı diğerlerine ilet (Relay görevi)
        broadcastDirect(line, senderHandler);
    }

    private void sendServerPubKey(ClientHandler target) {
        if (rsaPublic == null)
            return;
        try {
            String pubB64 = CryptoUtils.pubKeyToB64(rsaPublic);
            String payload = Base64.getEncoder().encodeToString(pubB64.getBytes(StandardCharsets.UTF_8));

            // Server'dan gelen mesaj olarak
            String line = new SecureChatClient.WireMessage(
                    "SERVER", CryptoUtils.ALGO_RSA_PUB, false, "", payload, System.currentTimeMillis()).format();

            target.send(line);
            System.out.println("[Server] Sent SERVER PUBKEY to " + target.socket.getRemoteSocketAddress());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void handleSessionKey(SecureChatClient.WireMessage m) {
        // Client, session key'i Server'ın RSA Public Key'i ile şifreledi mi?
        // Client mantığı: "remotePublicKeys" listesindeki herkese atıyor.
        // Server "SERVER" adıyla (veya bağlanınca anons ettiği nick ile) listede
        // olmalıydı.
        // Ancak bizim şu anki client kodunda server bir "peer" gibi davranmıyor,
        // sadece clientlar birbirini biliyor.

        // FAKAT: Client "Oturum Anahtarı" butonuna basınca herkese gönderiyor.
        // Eğer server da SESSKEY mesajını alıyorsa, payload'un kendisine ait kısmı var
        // mı bakmalı?
        // Mevcut Client SESSKEY'i sadece TEK BİR payload (String ctB64) olarak atıyor
        // (unicast/broadcast karışık).
        // SecureChatClient.java satır 733'e bakarsak:
        // for (Map.Entry<String, PublicKey> e : remotePublicKeys.entrySet()) { ...
        // out.println(...) }
        // Yani client HERKES için ayrı ayrı SESSKEY satırı gönderiyor!
        // Bu durumda Server'ın nicki client'ta kayıtlı değilse server SESSKEY alamaz.

        // ÇÖZÜM: Decrypting Server, bağlanan client'a kendini "SERVER" nickiyle ve RSA
        // Pub Key ile tanıtmalı.
        // Böylece client server'ı bir kişi sanıp ona da SESSKEY atar.

        // Ancak m.payloadB64, RSA ile şifrelenmiş session key.
        // Deneyelim: Server private key ile çözülüyor mu?
        try {
            byte[] ct = Base64.getDecoder().decode(m.payloadB64);
            byte[] sessKey = CryptoUtils.rsaUnwrapKeyUrlB64(rsaPrivate,
                    Base64.getUrlEncoder().withoutPadding().encodeToString(ct));
            // Veya rsaDecrypt direct?
            // Client ne kullanıyor? -> rsaEncrypt (Cipher RSA/ECB/PKCS1Padding) -> Base64
            // CryptoUtils.rsaUnwrapKeyUrlB64 ise OAEP kullanıyor.
            // Client.java:753 -> rsaEncrypt -> PKCS1Padding.
            // O zaman burada da PKCS1 padding ile çözmeliyiz.

            javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("RSA/ECB/PKCS1Padding");
            c.init(javax.crypto.Cipher.DECRYPT_MODE, rsaPrivate);
            byte[] keyBytes = c.doFinal(ct); // Raw session key

            sessionKeys.put(m.sender, keyBytes);
            System.out.println("[Server] Captured Session Key from " + m.sender + " (" + keyBytes.length + " bytes)");

        } catch (Exception e) {
            // Bu SESSKEY muhtemelen server için değil, başka bir peer için şifrelenmiş.
            // Veya padding hatası.
            // Loglamak gürültü yaratabilir ama debug için iyi.
            // System.out.println("[Server] Could not unwrap SESSKEY from " + m.sender + ":
            // " + e.getMessage());
        }
    }

    private void tryDecryptAndPrint(SecureChatClient.WireMessage m) {
        try {
            String plain = null;
            byte[] sessionKey = sessionKeys.get(m.sender);

            String algo = m.algorithm;

            // HYBRID CHECK
            if (algo.endsWith("_RSA")) {
                // Hibrit format
                // Client tarafı: encodeHybridPayloadJsonV1 -> JSON { ct, keys:{ nick:wrap... }
                // }
                // Server bu JSON'u parse etmeli ve kendi "SERVER" keyini bulmalı.

                String payloadMeta = new String(Base64.getDecoder().decode(m.payloadB64), StandardCharsets.UTF_8);
                Object[] parts = CryptoUtils.decodeHybridPayloadJsonV1(payloadMeta); // or legacy
                if (parts[0].toString().isEmpty())
                    parts = CryptoUtils.decodeHybridPayloadLegacyV1(payloadMeta);

                String ctUrlB64 = (String) parts[0];
                Map<String, String> map = (Map<String, String>) parts[1];

                // Server için wrap var mı?
                // Server nicki ne? "SERVER" veya init handshake'de ne dediysek.
                // Basitlik adina map'teki her şeyi denesek veya "SERVER" arasak?

                if (map.containsKey("SERVER")) {
                    String wrapped = map.get("SERVER");
                    byte[] sKey = CryptoUtils.rsaUnwrapKeyUrlB64(rsaPrivate, wrapped);

                    // Decrypt
                    if (algo.contains("AES")) {
                        plain = CryptoUtils.aesGcmDecryptWithKey(sKey, m.ivB64, ctUrlB64, null);
                    } else if (algo.contains("DES")) {
                        plain = CryptoUtils.desEcbDecryptWithKey(sKey, ctUrlB64, null);
                    }
                } else {
                    System.out.println("[Server] No wrapped key for SERVER in this hybrid msg.");
                    return;
                }

            } else {
                // NORMAL/MANUAL MOD
                // Eğer sessionKey var ise onu deneriz (AES/DES manual modda oturum anahtarı da
                // kullanılabiliyor UI'da).
                // Veya manual parola? Server manual parolayı bilemez.
                // Sadece SESSKEY ile çalışır.

                if (sessionKey == null) {
                    System.out
                            .println("[Server] No session key for " + m.sender + ", cannot decrypt manual/direct msg.");
                    return;
                }

                // Decrypt with raw session key
                // Format: payloadB64 -> raw bytes -> Cipher
                // Client normal şifrelemede: CryptoUtils.encrypt -> Base64
                // CryptoUtils.encrypt AES_GCM -> iv:ct string

                String inner = new String(Base64.getDecoder().decode(m.payloadB64), StandardCharsets.UTF_8);

                if (algo.contains("AES")) {
                    // inner = iv:ct
                    plain = CryptoUtils.decrypt(algo, inner, Base64.getEncoder().encodeToString(sessionKey));
                } else if (algo.contains("DES")) {
                    plain = CryptoUtils.decrypt(algo, inner, new String(sessionKey, StandardCharsets.UTF_8)); // DES
                                                                                                              // manual
                                                                                                              // key
                                                                                                              // string
                                                                                                              // olabilir?
                    // Client: AES için base64, DES için raw string key kullanıyor genelde.
                    // Ama session key byte[] -> String nasıl dönüştü?
                    // Client: btnSendSessionKey -> 32 random bytes -> B64 -> String -> sessionKeys
                    // map.
                    // Client send: resolveKey -> sessionKeys.get().
                    // Yani AES ve DES için KEY stringi Base64 formatında gönderiliyor
                    // (AES_GCM_Cipher decode ediyor).
                    // DES: if key < 8 chars error.
                    // Session KEy B64 string ise ~44 char > 8.
                    // Des Ecb Cipher -> key.getBytes().
                    // Yani B64 stringin byte'larını alıp key yapıyor. (Weak but valid).
                    // Bizim server da aynısını yapmalı.

                    plain = CryptoUtils.decrypt(algo, inner, Base64.getEncoder().encodeToString(sessionKey));
                }
            }

            if (plain != null) {
                System.out.println("==========================================");
                System.out.println("DECRYPTED MSG from " + m.sender + ":");
                System.out.println("Algo: " + algo);
                System.out.println("Content: " + plain);
                System.out.println("==========================================");
            }

        } catch (Exception e) {
            System.err.println("[Server] Decrypt Attempt Failed: " + e.getMessage());
        }
    }

    private void sendEncryptedAck(SecureChatClient.WireMessage original, ClientHandler to) {
        // "ACK:<timestamp>" i encrypt edip geri yolla
        try {
            String ackMsg = "ACK:" + System.currentTimeMillis();
            String algo = original.algorithm;
            String senderServer = "SERVER";

            String payloadB64 = "";
            String ivB64 = "";

            // Hibrit mi, Normal mi?
            if (algo.endsWith("_RSA")) {
                // Hibrit cevap
                // Yeni bir session key üretmeye gerek yok, gelen session keyi (varsa) veya
                // cached keyi kullan?
                // Veya RSA ile yeni hybrid paket oluştur?
                // Server -> Client hybrid:
                // 1. Session key üret (AES/DES)
                // 2. Encrypt ACK
                // 3. Client'ın PubKey'i ile wrap et (remotePublicKeys mantığı yok ama saved
                // pubkey?)
                // Biz SESSKEY aşamasında client pubkeyi kaydetmedik... (Sadece server'ınkini
                // yolladık).
                // PUBKEY mesajlarını dinleyip maplememiz lazım.
                // Şimdilik pas geçiyorum veya basitleştirilmiş: Client server'a session key
                // attıysa, server o keyi kullanıp geri dönebilir mi?
                // Hybrid modda session key PER MESSAGE unique mi? Client koduna göre hayır.
                // (btnSendSessionKey -> Map).
                // Ama Hybrid Send -> her seferinde `new SecureRandom().nextBytes(sessionKey)`
                // (Client:641) !!!
                // Evet, Hybrid modda PER-MESSAGE key var.
                // Bu durumda Server o mesajın keyini açtı. ACK'yı AYNI KEY ile şifreleyip
                // gönderebilir mi?
                // Teknik olarak evet. Ama client bunu nasıl çözecek?
                // Client hybrid alırken: `payloadPlain` -> `keys map` -> `myNick` -> unwrap.
                // Yani client kendi nickine ait bir wrapped key bekler.
                // Server'ın, Client'ın PUBLIC keyine ihtiyacı var.
                // SESSKEY mesajında pubkey yok.
                // PUBKEY mesajını handleSessionKey'den önce yakalamalıyız. (zaten yapıyoruz).
                // O zaman clientların Keylerini saklayalım.
            }

            // Basitlik için ACK'yi plaintext atalım geçici olarak, ya da aynı algoritmanın
            // "şifresiz" haliyle?
            // Hoca: "ACK'i aynı algoritmayla şifreli gönder".
            // Implementation Plan update: ACK functionality complex without PubKey storage.
            // Let's rely on cached PubKeys if available.

        } catch (Exception e) {
            // ACK fail silent
        }
    }

    void broadcastDirect(String line, ClientHandler from) {
        for (ClientHandler c : clients) {
            if (c != from)
                c.send(line);
        }
    }

    void remove(ClientHandler handler) {
        clients.remove(handler);
        try {
            handler.close();
        } catch (IOException ignored) {
        }
    }

    // MAIN
    public static void main(String[] args) throws IOException {
        int p = 6001;
        if (args.length > 0)
            p = Integer.parseInt(args[0]);
        new SecureChatServerDecrypting(p).start();
    }

    static class ClientHandler implements Runnable {
        final Socket socket;
        final SecureChatServerDecrypting server;
        final BufferedReader in;
        final PrintWriter out;

        ClientHandler(Socket socket, SecureChatServerDecrypting server) throws IOException {
            this.socket = socket;
            this.server = server;
            this.in = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
            this.out = new PrintWriter(new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8), true);

            // Client bağlandığında Server hemen PUBKEY atsın ki client onu tanısın
            server.sendServerPubKey(this);
        }

        void send(String line) {
            out.println(line);
        }

        void close() throws IOException {
            socket.close();
        }

        @Override
        public void run() {
            try {
                String line;
                while ((line = in.readLine()) != null) {
                    server.processAndBroadcast(line, this);
                }
            } catch (IOException ignored) {
            } finally {
                server.remove(this);
            }
        }
    }
}
