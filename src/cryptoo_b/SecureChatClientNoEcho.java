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

import javax.crypto.Cipher;

public class SecureChatClientNoEcho extends JFrame {

    private final JTextArea chatArea = new JTextArea();
    private final JTextField tfMessage = new JTextField();
    private final JButton btnSendPlain = new JButton("Gönder (Şifresiz)");
    private final JButton btnSendEncrypted = new JButton("Gönder (Şifreli)");
    private final JButton btnSendSessionKey = new JButton("Oturum Anahtarı (RSA)");

    private final String[] ALGO_OPTIONS = {
            "Caesar (Kaydırma)",
            "Vigenère",
            "Substitution (Yerine Koyma)",
            "Affine (Doğrusal)",
            "Playfair",
            "Rail Fence (Çit)",
            "Route (Spiral/Yol)",
            "Columnar (Sütunlama)",
            "Polybius 5x5",
            "Pigpen (Mason)",
            "AES-GCM (PBKDF2 / Oturum)",
            "DES (ECB)"
    };
    private final JComboBox<String> cbAlgo = new JComboBox<>(ALGO_OPTIONS);
    private final JTextField tfKey = new JTextField();
    private final JLabel lblKeyHint = new JLabel("Parola/Key formatı: (algoritmaya göre)");

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

    public SecureChatClientNoEcho() {
        super("Şifreli Sohbet (Client B)");

        initRSA();
        buildUI();
        bindActions();

        cbAlgo.addActionListener(e -> {
            String sel = (String) cbAlgo.getSelectedItem();
            if (sel != null) lblKeyHint.setText("Parola/Key formatı: " + hintFor(sel));
        });
    }

    private String hintFor(String algoName) {
        switch (algoName) {
            case "Caesar (Kaydırma)":                 return "Shift (tam sayı), ör: 3";
            case "Vigenère":                          return "Anahtar kelime, ör: GIZLI";
            case "Substitution (Yerine Koyma)":       return "29 harfli alfabe veya A:B;C:Ç;...";
            case "Affine (Doğrusal)":                 return "a,b (ör: 5,8) ve gcd(a,29)=1";
            case "Playfair":                          return "Anahtar kelime (I/J birleşik)";
            case "Rail Fence (Çit)":                  return "Ray sayısı (tam sayı)";
            case "Route (Spiral/Yol)":                return "Sütun sayısı, ops: 'ccw'";
            case "Columnar (Sütunlama)":              return "Anahtar kelime";
            case "Polybius 5x5":                      return "Anahtar yok";
            case "Pigpen (Mason)":                    return "Anahtar yok";
            case "AES-GCM (PBKDF2 / Oturum)":         return "Parola veya (boş → oturum anahtarı)";
            case "DES (ECB)":                         return "Anahtar (en az 8 karakter)";
            default:                                  return "-";
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
        if (t != null) t.interrupt();

        try { if (in != null) in.close(); } catch (Exception ignored) {}
        try { if (out != null) out.close(); } catch (Exception ignored) {}
        try { if (socket != null) socket.close(); } catch (Exception ignored) {}

        in = null; out = null; socket = null;
        btnConnect.setText("Bağlan");
        appendInfo("Bağlantı kapatıldı.");
    }

    private void readerLoop() {
        try {
            String line;
            while (!Thread.currentThread().isInterrupted()
                    && (line = in.readLine()) != null) {
                final String show = handleIncoming(line);
                if (show != null && !show.isEmpty()) {
                    SwingUtilities.invokeLater(() -> chatArea.append(show + "\n"));
                }
            }
        } catch (IOException ignored) {
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
                if (parts.length != 6) return null;
                String sender = uns(parts[0]);
                String algo   = uns(parts[1]);
                boolean enc   = Boolean.parseBoolean(parts[2]);
                String iv     = uns(parts[3]);
                String pl     = uns(parts[4]);
                long ts       = Long.parseLong(parts[5]);
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
        WireMessage m = WireMessage.parse(line);
        if (m == null) return "[HATA] Geçersiz satır: " + line;

        if ("PUBKEY".equals(m.algorithm)) {
            try {
                byte[] keyBytes = Base64.getDecoder().decode(m.payloadB64);
                KeyFactory kf = KeyFactory.getInstance("RSA");
                PublicKey pk = kf.generatePublic(new X509EncodedKeySpec(keyBytes));
                remotePublicKeys.put(m.sender, pk);
                return "[INFO] " + m.sender + " için RSA public key alındı.";
            } catch (Exception e) {
                return "[HATA] PUBKEY çözülürken hata: " + e.getMessage();
            }
        }

        if ("SESSKEY".equals(m.algorithm)) {
            try {
                byte[] ct = Base64.getDecoder().decode(m.payloadB64);
                byte[] pt = rsaDecrypt(ct);
                String sessionKey = new String(pt, StandardCharsets.UTF_8);
                sessionKeys.put(m.sender, sessionKey);
                return "[INFO] " + m.sender + " için oturum anahtarı alındı (RSA).";
            } catch (Exception e) {
                return "[HATA] SESSKEY çözülürken hata: " + e.getMessage();
            }
        }

        String decrypted;
        boolean ok = false;
        try {
            if (!m.encrypted || CryptoUtils.ALGO_NONE.equals(m.algorithm)) {
                decrypted = new String(
                        Base64.getDecoder().decode(m.payloadB64),
                        StandardCharsets.UTF_8
                );
                ok = true;
            } else {
                String raw = new String(
                        Base64.getDecoder().decode(m.payloadB64),
                        StandardCharsets.UTF_8
                );
                String keyForDec = resolveKeyForIncoming(m.algorithm, m.sender);
                decrypted = CryptoUtils.decrypt(
                        m.algorithm,
                        raw,
                        keyForDec
                );
                ok = true;
            }
        } catch (Exception ex) {
            decrypted = "(Çözüm hata: " + ex.getMessage() + ")";
        }

        return String.format("[%s] alg=%s enc=%s ⇒ %s",
                m.sender, m.algorithm, m.encrypted,
                decrypted + (ok ? "" : "  (RAW: " + line + ")"));
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
        if (s == null) return CryptoUtils.ALGO_NONE;

        if (s.startsWith("Caesar"))        return CryptoUtils.ALGO_CAESAR;
        if (s.startsWith("Vigen"))         return CryptoUtils.ALGO_VIGENERE;
        if (s.startsWith("Substitution"))  return CryptoUtils.ALGO_SUBST;
        if (s.startsWith("Affine"))        return CryptoUtils.ALGO_AFFINE;
        if (s.startsWith("Playfair"))      return CryptoUtils.ALGO_PLAYFAIR;
        if (s.startsWith("Rail Fence"))    return CryptoUtils.ALGO_RAILFENCE;
        if (s.startsWith("Route"))         return CryptoUtils.ALGO_ROUTE;
        if (s.startsWith("Columnar"))      return CryptoUtils.ALGO_COLUMNAR;
        if (s.startsWith("Polybius"))      return CryptoUtils.ALGO_POLYBIUS;
        if (s.startsWith("Pigpen"))        return CryptoUtils.ALGO_PIGPEN;
        if (s.startsWith("AES-GCM"))       return CryptoUtils.ALGO_AES_GCM;
        if (s.startsWith("DES"))           return CryptoUtils.ALGO_DES;

        return CryptoUtils.ALGO_NONE;
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
            throw new IllegalStateException("AES-GCM için parola ya da oturum anahtarı yok. (Önce 'Oturum Anahtarı (RSA)' gönder veya key gir.)");
        }
        return tfKey.getText();
    }

    private void sendMessage(boolean encrypted) {
        if (out == null) {
            toast("Önce sunucuya bağlan.");
            return;
        }

        String msg = tfMessage.getText();
        if (msg.isEmpty()) return;

        String algoCode = encrypted ? getSelectedAlgoCode() : CryptoUtils.ALGO_NONE;
        String sender   = tfNick.getText().trim().isEmpty()
                ? "Anon"
                : tfNick.getText().trim();

        String ivB64 = "";
        String payloadB64;

        try {
            if (!encrypted || CryptoUtils.ALGO_NONE.equals(algoCode)) {
                payloadB64 = Base64.getEncoder().encodeToString(
                        msg.getBytes(StandardCharsets.UTF_8));
            } else {
                String key = resolveKeyForOutgoing(algoCode);
                String enc = CryptoUtils.encrypt(algoCode, msg, key);
                payloadB64 = Base64.getEncoder().encodeToString(
                        enc.getBytes(StandardCharsets.UTF_8));
            }
        } catch (Exception e) {
            toast("Şifreleme hatası: " + e.getMessage());
            return;
        }

        WireMessage w = new WireMessage(
                sender, algoCode, encrypted, ivB64,
                payloadB64, System.currentTimeMillis()
        );
        out.println(w.format());
        tfMessage.setText("");
    }

    private void initRSA() {
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(2048);
            rsaKeyPair = gen.generateKeyPair();
            rsaPublic  = rsaKeyPair.getPublic();
            rsaPrivate = rsaKeyPair.getPrivate();
            appendInfo("RSA anahtar çifti oluşturuldu.");
        } catch (Exception e) {
            appendInfo("RSA init hata: " + e.getMessage());
        }
    }

    private void sendPublicKey() {
        if (out == null || rsaPublic == null) return;
        String nick = tfNick.getText().trim().isEmpty() ? "Anon" : tfNick.getText().trim();
        String pubB64 = Base64.getEncoder().encodeToString(rsaPublic.getEncoded());
        WireMessage w = new WireMessage(
                nick, "PUBKEY", false, "",
                pubB64, System.currentTimeMillis()
        );
        out.println(w.format());
        appendInfo("Public key yayınlandı.");
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
                        ctB64, System.currentTimeMillis()
                );
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
