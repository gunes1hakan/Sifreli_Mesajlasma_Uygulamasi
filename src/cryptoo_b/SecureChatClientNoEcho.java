package cryptoo_b;

import cryptoo.CryptoUtils;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.BorderFactory;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.List;
import java.util.ArrayList;

import javax.crypto.Cipher;

public class SecureChatClientNoEcho extends JFrame {

    private final JTextArea chatArea = new JTextArea();
    private final JTextField tfMessage = new JTextField();
    private final JButton btnSendPlain = new JButton("Gönder (Şifresiz)");
    private final JButton btnSendEncrypted = new JButton("Gönder (Şifreli)");
    private final JButton btnSendSessionKey = new JButton("Oturum Anahtarı (RSA)");

    private final JComboBox<String> cbAlgo;
    private final JTextField tfKey = new JTextField();
    private final JLabel lblKeyHint = new JLabel("Parola/Key formatı: (algoritmaya göre)");
    private final JLabel lblTiming = new JLabel("Süre: -");

    private final JTextField tfHost = new JTextField("127.0.0.1");
    private final JTextField tfPort = new JTextField("6000");
    private final JTextField tfNick = new JTextField("ClientB-" + (int) (Math.random() * 1000));
    private final JButton btnConnect = new JButton("Bağlan");

    private volatile Socket socket;
    private volatile BufferedReader in;
    private volatile PrintWriter out;
    private volatile Thread readerThread;

    // RSA & oturum anahtarı
    private KeyPair rsaKeyPair;
    private PublicKey rsaPublic;
    private PrivateKey rsaPrivate;
    private final SecureRandom rnd = new SecureRandom();

    private final Map<String, PublicKey> remotePublicKeys = new HashMap<>();
    private final Map<String, String> sessionKeys = new HashMap<>();

    // Rate limiting for PUBREQ replies
    private final Map<String, Long> lastPubSentMs = new HashMap<>();
    private static final long PUB_RESEND_DELAY_MS = 2000;

    public SecureChatClientNoEcho() {
        super("Şifreli Sohbet (Client B)");

        // Dinamik algoritma listesi
        java.util.List<String> algos = new java.util.ArrayList<>();
        algos.add("Caesar (Kaydırma)");
        algos.add("Vigenère");
        algos.add("Substitution (Yerine Koyma)");
        algos.add("Affine (Doğrusal)");
        algos.add("Playfair");
        algos.add("Rail Fence (Çit)");
        algos.add("Route (Spiral/Yol)");
        algos.add("Columnar (Sütunlama)");
        algos.add("Polybius 5x5");
        algos.add("Pigpen (Mason)");
        algos.add("Hill");
        algos.add("3DES (DESede)");
        algos.add("Blowfish");
        algos.add("GOST 28147");
        algos.add("AES-128 (LIB/JCE) - Password");
        algos.add("DES (LIB/JCE) - Password");
        algos.add("DES (MANUAL) - Feistel");
        algos.add("AES (MANUAL) - SPN");

        if (CryptoUtils.isBcAvailable()) {
            algos.add("AES-128 (LIB/BC) - Password");
            algos.add("DES (LIB/BC) - Password");
        }

        // RSA Hybrid Options
        algos.add("AES-128 (HYBRID RSA\u2192AES) (JCE)");
        algos.add("DES (HYBRID RSA\u2192DES) (JCE)");
        if (CryptoUtils.isBcAvailable()) {
            algos.add("AES-128 (HYBRID RSA\u2192AES) (BC)");
            algos.add("DES (HYBRID RSA\u2192DES) (BC)");
        }

        cbAlgo = new JComboBox<>(algos.toArray(new String[0]));

        initRSA();
        buildUI();
        bindActions();

        cbAlgo.addActionListener(e -> {
            String sel = (String) cbAlgo.getSelectedItem();
            if (sel != null)
                lblKeyHint.setText("Parola/Key formatı: " + hintFor(sel));
        });
    }

    private String hintFor(String algoName) {
        switch (algoName) {
            case "Caesar (Kaydırma)":
                return "Shift (tam sayı), ör: 3";
            case "Vigenère":
                return "Anahtar kelime, ör: GIZLI";
            case "Substitution (Yerine Koyma)":
                return "29 harfli alfabe veya A:B;C:Ç;...";
            case "Affine (Doğrusal)":
                return "a,b (ör: 5,8) ve gcd(a,29)=1";
            case "Playfair":
                return "Anahtar kelime (I/J birleşik)";
            case "Rail Fence (Çit)":
                return "Ray sayısı (tam sayı)";
            case "Route (Spiral/Yol)":
                return "Sütun sayısı, ops: 'ccw'";
            case "Columnar (Sütunlama)":
                return "Anahtar kelime";
            case "Polybius 5x5":
                return "Anahtar yok";
            case "Pigpen (Mason)":
                return "Anahtar yok";
            case "AES-128 (LIB/JCE) - Password":
                return "Parola ('password' yazın, boş bırakmayın)";
            case "DES (LIB/JCE) - Password":
                return "Anahtar (en az 8 karakter)";
            case "AES-128 (LIB/BC) - Password":
                return "Parola (BouncyCastle)";
            case "DES (LIB/BC) - Password":
                return "Anahtar (BouncyCastle)";
            case "AES-128 (HYBRID RSA\u2192AES) (JCE)":
            case "AES-128 (HYBRID RSA\u2192AES) (BC)":
            case "DES (HYBRID RSA\u2192DES) (JCE)":
            case "DES (HYBRID RSA\u2192DES) (BC)":
                return "PUBKEY gerekli (Key alanı yoksayılır)";
            case "DES (MANUAL) - Feistel":
                return "Key (Zorunlu) - Server decrypt etmez";
            case "AES (MANUAL) - SPN":
                return "Key (Zorunlu) - Server decrypt etmez";
            default:
                return "-";
        }
    }

    private JPanel labeled(String title, JComponent c) {
        JPanel p = new JPanel(new BorderLayout(2, 2));
        if (title != null && !title.isEmpty()) {
            JLabel l = new JLabel(title);
            l.setLabelFor(c);
            p.add(l, BorderLayout.NORTH);
        }
        p.add(c, BorderLayout.CENTER);
        return p;
    }

    private TitledBorder box(String title) {
        return BorderFactory.createTitledBorder(title);
    }

    private void buildUI() {
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setSize(900, 600);
        setLocationRelativeTo(null);

        chatArea.setEditable(false);
        chatArea.setLineWrap(true);
        chatArea.setWrapStyleWord(true);

        tfHost.setColumns(10);
        tfPort.setColumns(5);
        tfNick.setColumns(10);
        tfKey.setColumns(10);

        JPanel connRow = new JPanel(new GridLayout(1, 4, 8, 8));
        connRow.setBorder(box("Bağlantı"));
        connRow.add(labeled("Host", tfHost));
        connRow.add(labeled("Port", tfPort));
        connRow.add(labeled("Nick", tfNick));
        connRow.add(labeled(" ", btnConnect));

        JPanel msgRow = new JPanel(new GridLayout(1, 4, 8, 8));
        msgRow.setBorder(box("Mesaj Ayarları"));
        msgRow.add(labeled("Algoritma", cbAlgo));
        msgRow.add(labeled("Key / Parola", tfKey));
        msgRow.add(labeled("İpucu", lblKeyHint));

        JPanel sendButtons = new JPanel(new GridLayout(1, 3, 4, 4));
        sendButtons.add(btnSendPlain);
        sendButtons.add(btnSendEncrypted);
        sendButtons.add(btnSendSessionKey);
        msgRow.add(sendButtons);

        JScrollPane scroll = new JScrollPane(chatArea);

        JPanel bottom = new JPanel(new BorderLayout(8, 8));
        bottom.add(new JLabel("Mesaj"), BorderLayout.WEST);
        bottom.add(tfMessage, BorderLayout.CENTER);
        bottom.add(lblTiming, BorderLayout.EAST);

        JPanel top = new JPanel(new GridLayout(2, 1, 8, 8));
        top.setBorder(new EmptyBorder(8, 8, 0, 8));
        top.add(connRow);
        top.add(msgRow);

        setLayout(new BorderLayout(8, 8));
        add(top, BorderLayout.NORTH);
        add(scroll, BorderLayout.CENTER);
        add(bottom, BorderLayout.SOUTH);
    }

    private void bindActions() {
        btnConnect.addActionListener(this::toggleConnection);
        btnSendPlain.addActionListener(e -> sendMessage(false));
        btnSendEncrypted.addActionListener(e -> sendMessage(true));
        tfMessage.addActionListener(e -> sendMessage(true));
        btnSendSessionKey.addActionListener(e -> sendSessionKey());
    }

    private void toggleConnection(ActionEvent e) {
        if (socket != null && socket.isConnected() && !socket.isClosed()) {
            disconnect();
        } else {
            connect();
        }
    }

    private void connect() {
        String host = tfHost.getText().trim();
        int port;
        try {
            port = Integer.parseInt(tfPort.getText().trim());
        } catch (Exception ex) {
            toast("Port hatalı");
            return;
        }

        try {
            socket = new Socket(host, port);
            in = new BufferedReader(new InputStreamReader(
                    socket.getInputStream(), StandardCharsets.UTF_8));
            out = new PrintWriter(new OutputStreamWriter(
                    socket.getOutputStream(), StandardCharsets.UTF_8), true);

            readerThread = new Thread(this::readerLoop, "Reader-B");
            readerThread.start();

            btnConnect.setText("Kes");
            appendInfo("Bağlandı: " + host + ":" + port);

            sendPublicKey();
        } catch (IOException ex) {
            toast("Bağlanılamadı: " + ex.getMessage());
        }
    }

    private void disconnect() {
        Thread t = readerThread;
        readerThread = null;
        if (t != null)
            t.interrupt();

        try {
            if (in != null)
                in.close();
        } catch (Exception ignored) {
        }
        try {
            if (out != null)
                out.close();
        } catch (Exception ignored) {
        }
        try {
            if (socket != null)
                socket.close();
        } catch (Exception ignored) {
        }

        in = null;
        out = null;
        socket = null;
        btnConnect.setText("Bağlan");
        appendInfo("Bağlantı kapatıldı.");
    }

    private void readerLoop() {
        try {
            String line;
            while (!Thread.currentThread().isInterrupted()
                    && (line = in.readLine()) != null) {
                System.out.println("DEBUG: Socket read line: " + line); // Debug log
                try {
                    final String show = handleIncoming(line);
                    if (show != null && !show.isEmpty()) {
                        SwingUtilities.invokeLater(() -> chatArea.append(show + "\n"));
                    }
                } catch (Throwable t) {
                    System.err.println("CRITICAL: Error processing incoming line: " + t.getMessage());
                    t.printStackTrace();
                    SwingUtilities.invokeLater(() -> chatArea
                            .append("[SİSTEM HATASI] Mesaj işlenirken kritik hata: " + t.toString() + "\n"));
                }
            }
        } catch (IOException ignored) {
            System.err.println("Socket IO Exception: " + ignored.getMessage());
        } finally {
            SwingUtilities.invokeLater(() -> {
                btnConnect.setText("Bağlan");
                appendInfo("Sunucu ile bağlantı kesildi.");
            });
        }
    }

    static class WireMessage {
        final String sender;
        final String algorithm;
        final boolean encrypted;
        final String ivB64;
        final String payloadB64;
        final long ts;

        WireMessage(String sender, String algorithm,
                boolean encrypted, String ivB64,
                String payloadB64, long ts) {
            this.sender = sender;
            this.algorithm = algorithm;
            this.encrypted = encrypted;
            this.ivB64 = ivB64 == null ? "" : ivB64;
            this.payloadB64 = payloadB64;
            this.ts = ts;
        }

        String format() {
            return String.join("|",
                    safe(sender),
                    safe(algorithm),
                    Boolean.toString(encrypted),
                    safe(ivB64),
                    safe(payloadB64),
                    Long.toString(ts));
        }

        static WireMessage parse(String line) {
            try {
                String[] parts = line.split("\\|", 6);
                if (parts.length != 6)
                    return null;
                String sender = uns(parts[0]);
                String algo = uns(parts[1]);
                boolean enc = Boolean.parseBoolean(parts[2]);
                String iv = uns(parts[3]);
                String pl = uns(parts[4]);
                long ts = Long.parseLong(parts[5]);
                return new WireMessage(sender, algo, enc, iv, pl, ts);
            } catch (Exception e) {
                return null;
            }
        }

        static String safe(String s) {
            return s == null ? "" : s.replace("\n", " ");
        }

        static String uns(String s) {
            return s;
        }
    }

    private String handleIncoming(String line) {
        long start = System.nanoTime();
        try {
            String result = handleIncomingInternal(line);
            long end = System.nanoTime();
            if (result != null && !result.startsWith("[PUBKEY") && !result.startsWith("[PUBREQ")) {
                double elapsedMs = (end - start) / 1_000_000.0;
                SwingUtilities.invokeLater(() -> lblTiming.setText(String.format("Çözme: %.3f ms", elapsedMs)));
            }
            return result;
        } catch (Exception e) {
            return "[HATA] İşlem hatası: " + e.getMessage();
        }
    }

    private String handleIncomingInternal(String line) {
        WireMessage m = WireMessage.parse(line);
        if (m == null)
            return "[HATA] Geçersiz satır: " + line;

        // PUBKEY (RSA_PUB)
        if (CryptoUtils.ALGO_RSA_PUB.equals(m.algorithm)) {
            try {
                // Double-decoded: payloadB64 -> pubB64 string -> PublicKey
                String pubB64 = new String(Base64.getDecoder().decode(m.payloadB64), StandardCharsets.UTF_8);
                PublicKey pk = CryptoUtils.pubKeyFromB64(pubB64);
                String senderNick = m.sender.trim();
                remotePublicKeys.put(senderNick, pk);
                System.out.println("[PUBKEY] stored for nick=" + senderNick + " key=" + pk.getAlgorithm());
                return null;
            } catch (Exception e) {
                return "[HATA] RSA_PUB çözülürken hata: " + e.getMessage();
            }
        }

        // PUBREQ (RSA_PUBREQ)
        if (CryptoUtils.ALGO_RSA_PUBREQ.equals(m.algorithm)) {
            String reqNick = m.sender;
            long now = System.currentTimeMillis();
            Long last = lastPubSentMs.get(reqNick);

            if (last != null && (now - last < PUB_RESEND_DELAY_MS)) {
                System.out.println("[PUBREQ] skipped rate-limit for=" + reqNick);
                return null;
            }

            lastPubSentMs.put(reqNick, now);
            System.out.println("[PUBREQ] from=" + reqNick + " -> sending PUBKEY");
            sendPublicKey();

            return null;
        }

        // HYBRID DECRYPTION (AES/DES + RSA)
        if (m.algorithm.endsWith("_RSA")) {
            try {
                String payloadPlain = new String(Base64.getDecoder().decode(m.payloadB64), StandardCharsets.UTF_8);
                System.out.println("[HYBRID_DEBUG] Algo=" + m.algorithm + " IV=" + m.ivB64);
                System.out.println("[HYBRID_DEBUG] PayloadPlain=" + payloadPlain);

                // 2. Decode JSON or Legacy
                String ctUrlB64;
                Map<String, String> keysMap;

                if (payloadPlain.trim().startsWith("{")) {
                    Object[] res = CryptoUtils.decodeHybridPayloadJsonV1(payloadPlain);
                    ctUrlB64 = (String) res[0];
                    keysMap = (Map<String, String>) res[1];
                } else {
                    Object[] res = CryptoUtils.decodeHybridPayloadLegacyV1(payloadPlain);
                    ctUrlB64 = (String) res[0];
                    keysMap = (Map<String, String>) res[1];
                }

                if (ctUrlB64 == null || keysMap == null || keysMap.isEmpty()) {
                    return "[HATA] Hybrid format çözülemedi: " + payloadPlain;
                }

                // 3. Find my wrapped key
                String myNick = tfNick.getText().trim();
                String myWrapped = keysMap.get(myNick);
                if (myWrapped == null) {
                    // Try case-insensitive lookup
                    for (Map.Entry<String, String> e : keysMap.entrySet()) {
                        if (e.getKey().equalsIgnoreCase(myNick)) {
                            myWrapped = e.getValue();
                            break;
                        }
                    }
                }

                if (myWrapped == null) {
                    System.out.println("[HYBRID] no wrapped key for me: nick=" + myNick);
                    return "[" + m.sender + "] (Bu mesaj size şifrelenmemiş/key yok)";
                }

                // 4. Unwrap
                System.out.println("[HYBRID] found wrapped key for me: nick=" + myNick);
                byte[] sessionKey = CryptoUtils.rsaUnwrapKeyUrlB64(rsaPrivate, myWrapped);

                // 5. Decrypt Symmetric
                String plain = null;
                // Provider Selection
                // Provider Selection
                String provider = null;
                if (m.algorithm.contains("_BC") && CryptoUtils.isBcAvailable()) {
                    provider = "BC";
                }

                if (m.algorithm.contains("AES-GCM") || m.algorithm.contains("AES_GCM")) {
                    plain = CryptoUtils.aesGcmDecryptWithKey(sessionKey, m.ivB64, ctUrlB64, provider);
                } else if (m.algorithm.contains("DES")) {
                    plain = CryptoUtils.desEcbDecryptWithKey(sessionKey, ctUrlB64, provider);
                } else {
                    return "[HATA] Bilinmeyen Hybrid algo: " + m.algorithm;
                }

                return String.format("[%s] %s", m.sender, plain);

            } catch (Exception e) {
                return "[HATA] Hybrid çözüm hatası: " + e.getMessage();
            }
        }

        // SESSKEY (Old Legacy)

        String decrypted;
        boolean ok = false;
        try {
            if (!m.encrypted || CryptoUtils.ALGO_NONE.equals(m.algorithm)) {
                decrypted = new String(
                        Base64.getDecoder().decode(m.payloadB64),
                        StandardCharsets.UTF_8);
                ok = true;
            } else {
                String raw = new String(
                        Base64.getDecoder().decode(m.payloadB64),
                        StandardCharsets.UTF_8);
                String keyForDec = resolveKeyForIncoming(m.algorithm, m.sender);

                String algoToUse = m.algorithm;
                if (CryptoUtils.ALGO_AES_GCM_BC.equals(algoToUse) && !CryptoUtils.isBcAvailable()) {
                    algoToUse = CryptoUtils.ALGO_AES_GCM;
                } else if (CryptoUtils.ALGO_DES_BC.equals(algoToUse) && !CryptoUtils.isBcAvailable()) {
                    algoToUse = CryptoUtils.ALGO_DES;
                }

                decrypted = CryptoUtils.decrypt(
                        algoToUse,
                        raw,
                        keyForDec);
                ok = true;
            }
        } catch (Exception ex) {
            decrypted = "(Çözüm hata: " + ex.getMessage() + ")";
        }

        if (ok) {
            return String.format("[%s] %s", m.sender, decrypted);
        } else {
            return String.format("[%s] [Şifreli? %s] %s (RAW: %s)", m.sender, m.algorithm, decrypted, line);
        }
    }

    private String resolveKeyForIncoming(String algo, String senderNick) {
        if (CryptoUtils.ALGO_AES_GCM.equals(algo)) {
            String sess = sessionKeys.get(senderNick);
            if (sess != null && !sess.isEmpty()) {
                return sess;
            }
        }
        return tfKey.getText();
    }

    private String getSelectedAlgoCode() {
        String s = (String) cbAlgo.getSelectedItem();
        return cryptoo.crypto.ui.AlgoLabelMapper.toCode(s);
    }

    private String resolveKeyForOutgoing(String algoCode) {
        if (CryptoUtils.ALGO_AES_GCM.equals(algoCode)) {
            String manual = tfKey.getText();
            if (manual != null && !manual.isEmpty()) {
                return manual;
            }
            String selfNick = tfNick.getText().trim();
            String sess = sessionKeys.get(selfNick);
            if (sess != null && !sess.isEmpty()) {
                return sess;
            }
            throw new IllegalStateException(
                    "AES-GCM için parola ya da oturum anahtarı yok. (Önce 'Oturum Anahtarı (RSA)' gönder veya key gir.)");
        }
        if (algoCode.endsWith("_RSA")) {
            return null; // Ignored
        }
        return tfKey.getText();
    }

    private void sendMessage(boolean encrypted) {
        if (out == null) {
            toast("Önce sunucuya bağlan.");
            return;
        }

        String msg = tfMessage.getText();
        if (msg.isEmpty())
            return;

        String algoCode = encrypted ? getSelectedAlgoCode() : CryptoUtils.ALGO_NONE;

        // Fallback check
        if (!CryptoUtils.isBcAvailable()) {
            if (CryptoUtils.ALGO_AES_GCM_BC.equals(algoCode)) {
                toast("BC provider bulunamadı, AES-GCM (default) ile gönderiliyor.");
                algoCode = CryptoUtils.ALGO_AES_GCM;
            } else if (CryptoUtils.ALGO_DES_BC.equals(algoCode)) {
                toast("BC provider bulunamadı, DES (default) ile gönderiliyor.");
                algoCode = CryptoUtils.ALGO_DES;
            }
        }

        String sender = tfNick.getText().trim().isEmpty()
                ? "Anon"
                : tfNick.getText().trim();

        String ivB64 = "";
        String payloadB64;

        try {
            long start = System.nanoTime();
            if (!encrypted || CryptoUtils.ALGO_NONE.equals(algoCode)) {
                payloadB64 = Base64.getEncoder().encodeToString(
                        msg.getBytes(StandardCharsets.UTF_8));
            } else if (algoCode.endsWith("_RSA")) {
                // HYBRID SEND LOGIC
                if (remotePublicKeys.isEmpty()) {
                    toast("Hiçbir alıcı Public Key'i (RSA) bulunamadı. Mesaj şifrelenemez.");
                    return;
                }

                // 1. Session Key
                byte[] sessionKey;
                if (algoCode.contains("AES")) {
                    sessionKey = new byte[16];
                } else { // DES
                    sessionKey = new byte[8];
                }
                new SecureRandom().nextBytes(sessionKey);

                // 2. Encrypt Content
                String ctUrlB64;
                String provider = null;
                if (algoCode.contains("_BC") && CryptoUtils.isBcAvailable()) {
                    provider = "BC";
                }

                if (algoCode.contains("AES")) {
                    String[] res = CryptoUtils.aesGcmEncryptWithKey(sessionKey, msg, provider);
                    ivB64 = res[0];
                    ctUrlB64 = res[1];
                } else { // DES
                    ivB64 = "";
                    ctUrlB64 = CryptoUtils.desEcbEncryptWithKey(sessionKey, msg, provider);
                }

                // 3. Wrap Keys
                // Filter out SELF.

                String myNick = sender;
                Map<String, String> wrappedKeysByNick = new HashMap<>();

                for (Map.Entry<String, PublicKey> entry : remotePublicKeys.entrySet()) {
                    String nick = entry.getKey();
                    if (nick.equalsIgnoreCase(myNick))
                        continue; // Skip self

                    String wrapped = CryptoUtils.rsaWrapKeyUrlB64(entry.getValue(), sessionKey);
                    wrappedKeysByNick.put(nick, wrapped);
                }

                if (wrappedKeysByNick.isEmpty()) {
                    toast("Henüz karşı tarafın RSA public key'i gelmedi.");
                    return;
                }

                System.out.println("[HYBRID] algo=" + algoCode + " peers=" + wrappedKeysByNick.keySet());

                // 4. Construct JSON Payload
                String payloadJson = CryptoUtils.encodeHybridPayloadJsonV1(ctUrlB64, wrappedKeysByNick);
                payloadB64 = Base64.getEncoder().encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));

            } else {
                String key = resolveKeyForOutgoing(algoCode);
                String enc = CryptoUtils.encrypt(algoCode, msg, key);
                payloadB64 = Base64.getEncoder().encodeToString(
                        enc.getBytes(StandardCharsets.UTF_8));
            }
            long end = System.nanoTime();
            double elapsedMs = (end - start) / 1_000_000.0;
            lblTiming.setText(String.format("Şifreleme: %.3f ms", elapsedMs));

            WireMessage w = new WireMessage(
                    sender, algoCode, encrypted, ivB64,
                    payloadB64, System.currentTimeMillis());
            out.println(w.format());
            tfMessage.setText("");

        } catch (Exception e) {
            e.printStackTrace();
            toast("Gönderim Hatası: " + e.getMessage());
            chatArea.append("[SİSTEM] Mesaj gönderilemedi: " + e.getMessage() + "\n");
        }
    }

    private void initRSA() {
        try {
            rsaKeyPair = CryptoUtils.genRsaKeyPair();
            rsaPublic = rsaKeyPair.getPublic();
            rsaPrivate = rsaKeyPair.getPrivate();
            appendInfo("RSA anahtar çifti oluşturuldu (2048-bit).");
        } catch (Exception e) {
            appendInfo("RSA init hata: " + e.getMessage());
        }
    }

    private void sendPublicKey() {
        if (out == null || rsaPublic == null)
            return;
        String nick = tfNick.getText().trim().isEmpty() ? "Anon" : tfNick.getText().trim();
        String pubB64 = CryptoUtils.pubKeyToB64(rsaPublic); // Get helper output
        String payloadB64 = Base64.getEncoder().encodeToString(pubB64.getBytes(StandardCharsets.UTF_8));

        WireMessage w = new WireMessage(
                nick, CryptoUtils.ALGO_RSA_PUB, false, "",
                payloadB64, System.currentTimeMillis());
        out.println(w.format());

        // Also send PUBREQ
        WireMessage req = new WireMessage(
                nick, CryptoUtils.ALGO_RSA_PUBREQ, false, "",
                "", System.currentTimeMillis());
        out.println(req.format());
        // appendInfo("Public key yayınlandı.");
    }

    private void sendSessionKey() {
        if (out == null) {
            toast("Önce sunucuya bağlan.");
            return;
        }
        if (remotePublicKeys.isEmpty()) {
            toast("Herhangi bir remote public key yok. Diğer client bağlanıp PUBKEY göndermeli.");
            return;
        }

        byte[] skBytes = new byte[32];
        rnd.nextBytes(skBytes);
        String sessionKey = Base64.getEncoder().encodeToString(skBytes);

        String selfNick = tfNick.getText().trim().isEmpty() ? "Anon" : tfNick.getText().trim();
        sessionKeys.put(selfNick, sessionKey);

        for (Map.Entry<String, PublicKey> e : remotePublicKeys.entrySet()) {
            try {
                PublicKey pk = e.getValue();
                byte[] ct = rsaEncrypt(pk, sessionKey.getBytes(StandardCharsets.UTF_8));
                String ctB64 = Base64.getEncoder().encodeToString(ct);

                WireMessage w = new WireMessage(
                        selfNick, "SESSKEY", true, "",
                        ctB64, System.currentTimeMillis());
                out.println(w.format());
            } catch (Exception ex) {
                appendInfo("Oturum anahtarı gönderilirken hata (" + e.getKey() + "): " + ex.getMessage());
            }
        }
        appendInfo("Oturum anahtarı RSA ile gönderildi.");
    }

    private byte[] rsaEncrypt(PublicKey pk, byte[] data) throws Exception {
        Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        c.init(Cipher.ENCRYPT_MODE, pk);
        return c.doFinal(data);
    }

    private byte[] rsaDecrypt(byte[] ct) throws Exception {
        Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        c.init(Cipher.DECRYPT_MODE, rsaPrivate);
        return c.doFinal(ct);
    }

    private void toast(String s) {
        JOptionPane.showMessageDialog(this, s);
    }

    private void appendInfo(String s) {
        chatArea.append("[INFO] " + s + "\n");
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new SecureChatClientNoEcho().setVisible(true));
    }
}
