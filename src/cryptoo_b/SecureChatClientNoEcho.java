package cryptoo_b;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.BorderFactory;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public class SecureChatClientNoEcho extends JFrame {

    // ---- UI
    private final JTextArea chatArea = new JTextArea();
    private final JTextField tfMessage = new JTextField();
    private final JButton btnSendPlain = new JButton("Gönder (Şifresiz)");
    private final JButton btnSendEncrypted = new JButton("Gönder (Şifreli)");

    // --- Algoritma seçenekleri & UI öğeleri ---
private final String[] ALGO_OPTIONS = {
    "Caesar (Kaydırma)",
    "Vigenère",
    "Substitution (Basit Yerine Koyma)",
    "Affine (Doğrusal)",
    "Playfair",
    "Rail Fence (Çit)",
    "Route (Spiral/Yol)",
    "Columnar (Sütunlama)",
    "Polybius 5x5",
    "Pigpen (Mason)"
};
private final JComboBox<String> cbAlgo = new JComboBox<>(ALGO_OPTIONS);
private final JTextField tfKey = new JTextField();
private final JLabel lblKeyHint = new JLabel("Parola/Key formatı: (algoritmaya göre)");
private String hintFor(String algoName) {
    switch (algoName) {
        case "Caesar (Kaydırma)": return "Shift (tam sayı), ör: 3";
        case "Vigenère": return "Anahtar (sözcük), ör: GIZLI";
        case "Substitution (Basit Yerine Koyma)": return "29 harfli harita veya A:B;C:Ç;…";
        case "Affine (Doğrusal)": return "a,b (ör: 5,8) ve gcd(a,29)=1";
        case "Playfair": return "Anahtar kelime (I/J birleşik)";
        case "Rail Fence (Çit)": return "Ray sayısı (tam sayı)";
        case "Route (Spiral/Yol)": return "Sütun sayısı (tam sayı), ops: 'ccw'";
        case "Columnar (Sütunlama)": return "Anahtar (sözcük)";
        case "Polybius 5x5": return "Anahtar yok";
        case "Pigpen (Mason)": return "Anahtar yok";
        default: return "-";
    }
}
private final JTextField tfHost = new JTextField("127.0.0.1");
    private final JTextField tfPort = new JTextField("6000");
    private final JTextField tfNick = new JTextField("ClientB-" + (int)(Math.random()*1000));
    private final JButton btnConnect = new JButton("Bağlan");

    // ---- Network
    private volatile Socket socket;
    private volatile BufferedReader in;
    private volatile PrintWriter out;
    private volatile Thread readerThread;

    public SecureChatClientNoEcho() {
        super("Şifreli Sohbet — Client B (No Echo)");
        buildUI();
        bindActions();
    
        cbAlgo.addActionListener(e -> { String sel=(String)cbAlgo.getSelectedItem(); if (sel!=null) lblKeyHint.setText("Parola/Key formatı: "+hintFor(sel)); });
}

    // ---------- UI helpers ----------
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
    private TitledBorder box(String title) { return BorderFactory.createTitledBorder(title); }

    private void buildUI() {
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setSize(900, 600);
        setLocationRelativeTo(null);

        chatArea.setEditable(false);
        chatArea.setLineWrap(true);
        chatArea.setWrapStyleWord(true);

        tfHost.setColumns(12); tfPort.setColumns(6); tfNick.setColumns(12); tfKey.setColumns(12);
        tfHost.setToolTipText("Sunucu IP/Hostname (örn. 127.0.0.1)");
        tfPort.setToolTipText("Sunucu portu (örn. 6000)");
        tfNick.setToolTipText("Takma ad");
        tfKey.setToolTipText("CAESAR: sayı (0-255), XOR/AES: anahtar/parola");

        JPanel connRow = new JPanel(new GridLayout(1, 5, 8, 8));
        connRow.setBorder(box("Bağlantı"));
        connRow.add(labeled("Host", tfHost));
        connRow.add(labeled("Port", tfPort));
        connRow.add(labeled("Nick", tfNick));
        connRow.add(labeled(" ", btnConnect));

        JPanel msgRow = new JPanel(new GridLayout(1, 5, 8, 8));
        msgRow.setBorder(box("Mesaj Ayarları"));
        msgRow.add(labeled("Algoritma", cbAlgo));
        msgRow.add(labeled("Key / Shift", tfKey));
        msgRow.add(labeled("İpucu", lblKeyHint));
        msgRow.add(labeled("İpucu", lblKeyHint));
        msgRow.add(labeled(" ", btnSendPlain));
        msgRow.add(labeled(" ", btnSendEncrypted));

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
        tfMessage.addActionListener(e -> sendMessage(true)); // Enter => şifreli gönder
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
        try { port = Integer.parseInt(tfPort.getText().trim()); }
        catch (Exception ex) { toast("Port hatalı"); return; }

        try {
            socket = new Socket(host, port);
            in = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
            out = new PrintWriter(new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8), true);

            readerThread = new Thread(this::readerLoop, "ReaderB");
            readerThread.start();

            btnConnect.setText("Kes");
            appendInfo("Bağlandı: " + host + ":" + port);
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
            while (!Thread.currentThread().isInterrupted() && (line = in.readLine()) != null) {
                final String show = handleIncoming(line);
                SwingUtilities.invokeLater(() -> chatArea.append(show + "\n"));
            }
        } catch (IOException ignored) {
        } finally {
            SwingUtilities.invokeLater(() -> {
                btnConnect.setText("Bağlan");
                appendInfo("Sunucu ile bağlantı kesildi.");
            });
        }
    }

    private String handleIncoming(String line) {
    WireMessage m = WireMessage.parse(line);
    if (m == null) return "[HATA] Geçersiz satır: " + line;

    String algoSel = getSelectedAlgo();
    String key = tfKey.getText();

    String decrypted;
    boolean ok = false;
    try {
        if (!m.encrypted) {
            decrypted = new String(Base64.getDecoder().decode(m.payloadB64), StandardCharsets.UTF_8);
            ok = true;
        } else {
            String raw = new String(Base64.getDecoder().decode(m.payloadB64), StandardCharsets.UTF_8);
            decrypted = decryptDispatchCanonical(algoSel, raw, key);
            ok = true;
        }
    } catch (Exception ex) {
        decrypted = "(Çözüm hata: " + ex.getMessage() + ")";
    }

    return String.format("[%s] alg=%s enc=%s ⇒ %s",
            m.sender, m.algorithm, m.encrypted, decrypted + (ok ? "" : "  (RAW: " + line + ")"));
}


    private String getSelectedAlgo() {
    String s = (String) cbAlgo.getSelectedItem();
    if (s == null) return "NONE";
    if (s.startsWith("Caesar")) return "CAESAR";
    if (s.startsWith("Vigen")) return "VIGENERE";
    if (s.startsWith("Substitution")) return "SUBSTITUTION";
    if (s.startsWith("Affine")) return "AFFINE";
    if (s.startsWith("Playfair")) return "PLAYFAIR";
    if (s.startsWith("Rail Fence")) return "RAILFENCE";
    if (s.startsWith("Route")) return "ROUTE";
    if (s.startsWith("Columnar")) return "COLUMNAR";
    if (s.startsWith("Polybius")) return "POLYBIUS";
    if (s.startsWith("Pigpen")) return "PIGPEN";
    return "NONE";
}


 // *** NO ECHO DEĞİL: GÖNDERİRKEN HEM DÜZ METİN HEM ŞİFRELİ ÖNİZLEMEYİ GÖSTER ***
    private void sendMessage(boolean encrypted) {
    if (out == null) { toast("Önce bağlan."); return; }

    String msg = tfMessage.getText();
    if (msg.isEmpty()) return;

    String algo = encrypted ? getSelectedAlgo() : "NONE";
    String key = tfKey.getText();
    String sender = tfNick.getText().trim().isEmpty() ? "Anon" : tfNick.getText().trim();

    String ivB64 = "";
    String payloadB64;
    if (!encrypted || "NONE".equals(algo)) {
        payloadB64 = Base64.getEncoder().encodeToString(msg.getBytes(StandardCharsets.UTF_8));
    } else {
        String enc = encryptDispatchCanonical(algo, msg, key);
        payloadB64 = Base64.getEncoder().encodeToString(enc.getBytes(StandardCharsets.UTF_8));
    }

    WireMessage w = new WireMessage(
    	    sender, algo, encrypted, ivB64, payloadB64, System.currentTimeMillis()
    	);
    	out.println(w.format());

    tfMessage.setText("");
}



    private int parseShift(String key) {
        try {
            int s = Integer.parseInt(key.trim());
            return s & 0xFF;
        } catch (Exception e) {
            throw new IllegalArgumentException("CAESAR için sayı (0-255) gir");
        }
    }

    private void toast(String s) { JOptionPane.showMessageDialog(this, s); }
    private void appendInfo(String s) { chatArea.append("[INFO] " + s + "\n"); }

    // ---- Main
    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new SecureChatClientNoEcho().setVisible(true));
    }

    // ---- Wire format
    static class WireMessage {
        final String sender, algorithm, ivB64, payloadB64;
        final boolean encrypted;
        final long ts;

        WireMessage(String sender, String algorithm, boolean encrypted, String ivB64, String payloadB64, long ts) {
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
                String algo = uns(parts[1]);
                boolean enc = Boolean.parseBoolean(parts[2]);
                String iv = uns(parts[3]);
                String payload = uns(parts[4]);
                long ts = Long.parseLong(parts[5]);
                return new WireMessage(sender, algo, enc, iv, payload, ts);
            } catch (Exception e) {
                return null;
            }
        }

        static String safe(String s) { return s == null ? "" : s.replace("\n", " "); }
        static String uns(String s) { return s; }
    }

    // ---- Crypto utils
    static class Crypto {
        private static final SecureRandom RNG = new SecureRandom();
        private static final byte[] FIXED_SALT = "SecureChatFixedSalt".getBytes(StandardCharsets.UTF_8);

        static byte[] caesar(byte[] data, int shift0to255) {
            byte[] out = new byte[data.length];
            int sh = shift0to255 & 0xFF;
            for (int i = 0; i < data.length; i++) {
                out[i] = (byte) ((data[i] + sh) & 0xFF);
            }
            return out;
        }

        static byte[] xor(byte[] data, byte[] key) {
            if (key == null || key.length == 0) throw new IllegalArgumentException("XOR için anahtar boş olamaz");
            byte[] out = new byte[data.length];
            for (int i = 0; i < data.length; i++) {
                out[i] = (byte) (data[i] ^ key[i % key.length]);
            }
            return out;
        }

        static byte[] randomIV() {
            byte[] iv = new byte[12];
            RNG.nextBytes(iv);
            return iv;
        }

        static SecretKey deriveAesKey(char[] password) throws Exception {
            PBEKeySpec spec = new PBEKeySpec(password, FIXED_SALT, 65536, 256);
            SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] keyBytes = f.generateSecret(spec).getEncoded();
            return new SecretKeySpec(keyBytes, "AES");
        }

        static byte[] aesGcmEncrypt(byte[] plaintext, char[] password, byte[] iv) throws Exception {
            SecretKey key = deriveAesKey(password);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec spec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.ENCRYPT_MODE, key, spec);
            return cipher.doFinal(plaintext);
        }

        static byte[] aesGcmDecrypt(byte[] ciphertext, char[] password, byte[] iv) throws Exception {
            SecretKey key = deriveAesKey(password);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec spec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.DECRYPT_MODE, key, spec);
            return cipher.doFinal(ciphertext);
        }
    }

// ======== ORTAK YARDIMCILAR & TÜM KLASİK ŞİFRELER ========
private static final String TR_ALPHABET = "ABCÇDEFGĞHIİJKLMNOÖPRSŞTUÜVYZ";

private static boolean isTrLetter(char ch) {
    char u = Character.toUpperCase(ch);
    return TR_ALPHABET.indexOf(u) >= 0;
}
private static char safeChar(char ch) {
    if (isTrLetter(ch)) return Character.toUpperCase(ch);
    return ch;
}
private static String normalizeText(String s, boolean lettersOnly) {
    StringBuilder sb = new StringBuilder(s.length());
    for (int i = 0; i < s.length(); i++) {
        char c = safeChar(s.charAt(i));
        if (lettersOnly) {
            if (isTrLetter(c)) sb.append(c);
        } else {
            sb.append(c);
        }
    }
    return sb.toString();
}
private static int alphaIndex(char u) { return TR_ALPHABET.indexOf(u); }

// ---- Caesar ----
private static String caesarEncrypt(String text, int shift) {
    StringBuilder out = new StringBuilder(text.length());
    int n = TR_ALPHABET.length();
    for (int i = 0; i < text.length(); i++) {
        char c = text.charAt(i);
        char u = safeChar(c);
        int idx = TR_ALPHABET.indexOf(u);
        if (idx >= 0) {
            int ni = (idx + (shift % n) + n) % n;
            out.append(TR_ALPHABET.charAt(ni));
        } else out.append(c);
    }
    return out.toString();
}
private static String caesarDecrypt(String cipher, int shift) { return caesarEncrypt(cipher, -shift); }

// ---- Vigenère ----
private static String vigenereEncrypt(String text, String keyRaw) {
    String textN = normalizeText(text, false);
    String keyN  = normalizeText(keyRaw==null? "" : keyRaw, true);
    if (keyN.isEmpty()) return textN;
    StringBuilder out = new StringBuilder(textN.length());
    int n = TR_ALPHABET.length(), ki = 0;
    for (int i = 0; i < textN.length(); i++) {
        char c = textN.charAt(i);
        if (!isTrLetter(c)) { out.append(c); continue; }
        char kc = keyN.charAt(ki % keyN.length());
        int s = alphaIndex(kc);
        int ti = alphaIndex(c);
        out.append(TR_ALPHABET.charAt((ti + s) % n));
        ki++;
    }
    return out.toString();
}
private static String vigenereDecrypt(String cipher, String keyRaw) {
    String cN = normalizeText(cipher, false);
    String keyN = normalizeText(keyRaw==null? "" : keyRaw, true);
    if (keyN.isEmpty()) return cN;
    StringBuilder out = new StringBuilder(cN.length());
    int n = TR_ALPHABET.length(), ki = 0;
    for (int i = 0; i < cN.length(); i++) {
        char c = cN.charAt(i);
        if (!isTrLetter(c)) { out.append(c); continue; }
        char kc = keyN.charAt(ki % keyN.length());
        int s = alphaIndex(kc);
        int ci = alphaIndex(c);
        out.append(TR_ALPHABET.charAt((ci - s + n) % n));
        ki++;
    }
    return out.toString();
}

// ---- Substitution ----
private static String substitutionEncryptAuto(String text, String key) {
    int[] map = buildSubstitutionMap(key);
    return substitutionApply(text, map, true);
}
private static String substitutionDecryptAuto(String cipher, String key) {
    int[] map = buildSubstitutionMap(key);
    return substitutionApply(cipher, map, false);
}
private static int[] buildSubstitutionMap(String key) {
    int n = TR_ALPHABET.length();
    int[] map = new int[n];
    for (int i=0;i<n;i++) map[i]=i;
    if (key == null) return map;
    String kOnly = normalizeText(key, true);
    if (kOnly.length() == n) {
        for (int i=0;i<n;i++) {
            int j = TR_ALPHABET.indexOf(kOnly.charAt(i));
            if (j>=0) map[i]=j;
        }
        return map;
    }
    String[] pairs = key.split("[;\n]+");
    for (String p : pairs) {
        String[] ab = p.split(":");
        if (ab.length==2) {
            String a = normalizeText(ab[0], true);
            String b = normalizeText(ab[1], true);
            if (a.length()==1 && b.length()==1) {
                int ia = TR_ALPHABET.indexOf(a.charAt(0));
                int ib = TR_ALPHABET.indexOf(b.charAt(0));
                if (ia>=0 && ib>=0) map[ia]=ib;
            }
        }
    }
    return map;
}
private static String substitutionApply(String s, int[] map, boolean enc) {
    StringBuilder out = new StringBuilder(s.length());
    for (int i=0;i<s.length();i++) {
        char c = s.charAt(i);
        char u = safeChar(c);
        int idx = TR_ALPHABET.indexOf(u);
        if (idx>=0) {
            int t = enc ? map[idx] : inverseMap(map, idx);
            out.append(TR_ALPHABET.charAt(t));
        } else out.append(c);
    }
    return out.toString();
}
private static int inverseMap(int[] map, int y) { for (int i=0;i<map.length;i++) if (map[i]==y) return i; return y; }

// ---- Affine ----
private static String affineEncryptAuto(String text, String key) {
    int[] ab = parseAB(key);
    return affineEncrypt(text, ab[0], ab[1]);
}
private static String affineDecryptAuto(String cipher, String key) {
    int[] ab = parseAB(key);
    return affineDecrypt(cipher, ab[0], ab[1]);
}
private static int[] parseAB(String key) {
    int a=1,b=0;
    if (key!=null) {
        String[] t = key.split("[,; ]+");
        try { if (t.length>0) a = Integer.parseInt(t[0].trim()); } catch(Exception ignored){}
        try { if (t.length>1) b = Integer.parseInt(t[1].trim()); } catch(Exception ignored){}
    }
    return new int[]{a,b};
}
private static int egcdInv(int a, int m) {
    int t=0, newt=1, r=m, newr=a % m; if (newr<0) newr+=m;
    while (newr!=0) {
        int q = r / newr;
        int tmp = t - q*newt; t = newt; newt = tmp;
        tmp = r - q*newr; r = newr; newr = tmp;
    }
    if (r>1) return 1;
    if (t<0) t += m;
    return t;
}
private static String affineEncrypt(String text, int a, int b) {
    int n = TR_ALPHABET.length();
    StringBuilder out = new StringBuilder(text.length());
    for (int i=0;i<text.length();i++) {
        char c = text.charAt(i);
        char u = safeChar(c);
        int idx = TR_ALPHABET.indexOf(u);
        if (idx>=0) {
            int ni = (a*idx + b) % n; if (ni<0) ni+=n;
            out.append(TR_ALPHABET.charAt(ni));
        } else out.append(c);
    }
    return out.toString();
}
private static String affineDecrypt(String cipher, int a, int b) {
    int n = TR_ALPHABET.length();
    int ai = egcdInv(a, n);
    StringBuilder out = new StringBuilder(cipher.length());
    for (int i=0;i<cipher.length();i++) {
        char c = cipher.charAt(i);
        char u = safeChar(c);
        int idx = TR_ALPHABET.indexOf(u);
        if (idx>=0) {
            int ni = (ai * (idx - b)) % n; if (ni<0) ni+=n;
            out.append(TR_ALPHABET.charAt(ni));
        } else out.append(c);
    }
    return out.toString();
}

// ---- Rail Fence ----
private static String railFenceEncryptAuto(String text, String key) {
    int rails=2; try { rails = Integer.parseInt(key.trim()); } catch(Exception ignored){}
    return railFenceEncrypt(text, rails);
}
private static String railFenceDecryptAuto(String cipher, String key) {
    int rails=2; try { rails = Integer.parseInt(key.trim()); } catch(Exception ignored){}
    return railFenceDecrypt(cipher, rails);
}
private static String railFenceEncrypt(String text, int rails) {
    if (rails<=1) return text;
    StringBuilder[] rows = new StringBuilder[rails];
    for (int i=0;i<rails;i++) rows[i]=new StringBuilder();
    int r=0, dir=1;
    for (int i=0;i<text.length();i++) {
        rows[r].append(text.charAt(i));
        r += dir;
        if (r==rails-1) dir=-1;
        else if (r==0) dir=1;
    }
    StringBuilder out = new StringBuilder(text.length());
    for (int i=0;i<rails;i++) out.append(rows[i]);
    return out.toString();
}
private static String railFenceDecrypt(String cipher, int rails) {
    if (rails<=1) return cipher;
    int len = cipher.length();
    boolean[][] mark = new boolean[rails][len];
    int r=0, dir=1;
    for (int j=0;j<len;j++) {
        mark[r][j] = true;
        r += dir;
        if (r==rails-1) dir=-1;
        else if (r==0) dir=1;
    }
    char[][] grid = new char[rails][len];
    int idx=0;
    for (int i=0;i<rails;i++) {
        for (int j=0;j<len;j++) {
            if (mark[i][j]) grid[i][j] = cipher.charAt(idx++);
        }
    }
    StringBuilder res = new StringBuilder(len);
    r=0; dir=1;
    for (int j=0;j<len;j++) {
        res.append(grid[r][j]);
        r += dir;
        if (r==rails-1) dir=-1;
        else if (r==0) dir=1;
    }
    return res.toString();
}

// ---- Route (Spiral) ----
private static String routeEncryptAuto(String text, String key) {
    int cols = 3; boolean cw = true;
    if (key!=null && !key.isEmpty()) {
        String k = key.toLowerCase();
        try { cols = Integer.parseInt(k.replaceAll("[^0-9]", "")); } catch(Exception ignored){}
        if (k.contains("ccw") || k.contains("counter")) cw = false;
    }
    return routeEncrypt(text, cols, cw);
}
private static String routeDecryptAuto(String cipher, String key) {
    int cols = 3; boolean cw = true;
    if (key!=null && !key.isEmpty()) {
        String k = key.toLowerCase();
        try { cols = Integer.parseInt(k.replaceAll("[^0-9]", "")); } catch(Exception ignored){}
        if (k.contains("ccw") || k.contains("counter")) cw = false;
    }
    return routeDecrypt(cipher, cols, cw);
}
private static String routeEncrypt(String text, int cols, boolean clockwise) {
    if (cols<=1) return text;
    int len = text.length();
    int rows = (len + cols - 1)/cols;
    char[][] grid = new char[rows][cols];
    int idx=0;
    for (int i=0;i<rows;i++) for (int j=0;j<cols;j++) grid[i][j] = (idx<len)? text.charAt(idx++) : 0;
    StringBuilder out = new StringBuilder(len);
    int top=0, bottom=rows-1, left=0, right=cols-1, taken=0;
    while (top<=bottom && left<=right && taken<len) {
        if (clockwise) {
            for (int j=left;j<=right && taken<len;j++) { int pos=top*cols+j; if (pos<len){ out.append(grid[top][j]); taken++; } } top++;
            for (int i=top;i<=bottom && taken<len;i++) { int pos=i*cols+right; if (pos<len){ out.append(grid[i][right]); taken++; } } right--;
            if (top<=bottom) { for (int j=right;j>=left && taken<len;j--) { int pos=bottom*cols+j; if (pos<len){ out.append(grid[bottom][j]); taken++; } } bottom--; }
            if (left<=right) { for (int i=bottom;i>=top && taken<len;i--) { int pos=i*cols+left; if (pos<len){ out.append(grid[i][left]); taken++; } } left++; }
        } else {
            for (int i=top;i<=bottom && taken<len;i++) { int pos=i*cols+left; if (pos<len){ out.append(grid[i][left]); taken++; } } left++;
            for (int j=left;j<=right && taken<len;j++) { int pos=bottom*cols+j; if (pos<len){ out.append(grid[bottom][j]); taken++; } } bottom--;
            if (left<=right) { for (int i=bottom;i>=top && taken<len;i--) { int pos=i*cols+right; if (pos<len){ out.append(grid[i][right]); taken++; } } right--; }
            if (top<=bottom) { for (int j=right;j>=left && taken<len;j--) { int pos=top*cols+j; if (pos<len){ out.append(grid[top][j]); taken++; } } top++; }
        }
    }
    return out.toString();
}
private static String routeDecrypt(String cipher, int cols, boolean clockwise) {
    if (cols<=1) return cipher;
    int len = cipher.length();
    int rows = (len + cols - 1)/cols;
    char[][] grid = new char[rows][cols];
    int top=0, bottom=rows-1, left=0, right=cols-1, idx=0;
    while (top<=bottom && left<=right && idx<len) {
        if (clockwise) {
            for (int j=left;j<=right && idx<len;j++) { int pos=top*cols+j; if (pos<len) grid[top][j] = cipher.charAt(idx++); } top++;
            for (int i=top;i<=bottom && idx<len;i++) { int pos=i*cols+right; if (pos<len) grid[i][right] = cipher.charAt(idx++); } right--;
            if (top<=bottom) { for (int j=right;j>=left && idx<len;j--) { int pos=bottom*cols+j; if (pos<len) grid[bottom][j] = cipher.charAt(idx++); } bottom--; }
            if (left<=right) { for (int i=bottom;i>=top && idx<len;i--) { int pos=i*cols+left; if (pos<len) grid[i][left] = cipher.charAt(idx++); } left++; }
        } else {
            for (int i=top;i<=bottom && idx<len;i++) { int pos=i*cols+left; if (pos<len) grid[i][left] = cipher.charAt(idx++); } left++;
            for (int j=left;j<=right && idx<len;j++) { int pos=bottom*cols+j; if (pos<len) grid[bottom][j] = cipher.charAt(idx++); } bottom--;
            if (left<=right) { for (int i=bottom;i>=top && idx<len;i--) { int pos=i*cols+right; if (pos<len) grid[i][right] = cipher.charAt(idx++); } right--; }
            if (top<=bottom) { for (int j=right;j>=left && idx<len;j--) { int pos=top*cols+j; if (pos<len) grid[top][j] = cipher.charAt(idx++); } top++; }
        }
    }
    StringBuilder out = new StringBuilder(len);
    int count=0;
    for (int i=0;i<rows;i++) for (int j=0;j<cols;j++) { if (count<len) out.append(grid[i][j]); count++; }
    return out.toString();
}

// ---- Columnar ----
private static String columnarEncrypt(String text, String key) {
    if (key==null || key.isEmpty()) return text;
    String k = normalizeText(key, true); if (k.isEmpty()) return text;
    int cols = k.length(), len = text.length(), rows = (len + cols - 1)/cols;
    int[] order = columnOrder(k);
    StringBuilder out = new StringBuilder(len);
    for (int oi=0; oi<cols; oi++) {
        int col = order[oi];
        for (int r=0;r<rows;r++) {
            int idx = r*cols + col;
            if (idx < len) out.append(text.charAt(idx));
        }
    }
    return out.toString();
}
private static String columnarDecrypt(String cipher, String key) {
    if (key==null || key.isEmpty()) return cipher;
    String k = normalizeText(key, true); if (k.isEmpty()) return cipher;
    int cols = k.length(), len = cipher.length(), rows = (len + cols - 1)/cols, rem = len % cols;
    int[] order = columnOrder(k);
    int[] colHeights = new int[cols];
    for (int c=0;c<cols;c++) colHeights[c] = rows - ((rem!=0 && c>=rem) ? 1 : 0);
    char[][] grid = new char[rows][cols];
    int idx=0;
    for (int oi=0; oi<cols; oi++) {
        int col = order[oi], h = colHeights[col];
        for (int r=0;r<h;r++) grid[r][col] = cipher.charAt(idx++);
    }
    StringBuilder out = new StringBuilder(len);
    for (int r=0;r<rows;r++) for (int c=0;c<cols;c++) {
        int pos = r*cols + c; if (pos < len) out.append(grid[r][c]);
    }
    return out.toString();
}
private static int[] columnOrder(String k) {
    int n = k.length(); Integer[] idx = new Integer[n];
    for (int i=0;i<n;i++) idx[i]=i;
    java.util.Arrays.sort(idx, (a,b)->{
        char ca = k.charAt(a), cb = k.charAt(b);
        if (ca==cb) return Integer.compare(a,b);
        return Character.compare(ca, cb);
    });
    int[] order = new int[n];
    for (int i=0;i<n;i++) order[i]=idx[i];
    return order;
}

// ---- Polybius (5x5) ----
private static String polybiusEncrypt(String text) {
    String alpha = "ABCDEFGHIKLMNOPQRSTUVWXYZ";
    StringBuilder out = new StringBuilder();
    for (int i=0;i<text.length();i++) {
        char u = polyLatin(text.charAt(i));
        int p = alpha.indexOf(u);
        if (p>=0) { int r=p/5+1, c=p%5+1; out.append(r).append(c).append(' '); }
        else out.append(text.charAt(i));
    }
    return out.toString().trim();
}
private static String polybiusDecrypt(String cipher) {
    String alpha = "ABCDEFGHIKLMNOPQRSTUVWXYZ";
    StringBuilder out = new StringBuilder();
    for (int i=0;i<cipher.length();) {
        char a = cipher.charAt(i);
        if (a>='1' && a<='5' && i+1<cipher.length()) {
            char b = cipher.charAt(i+1);
            if (b>='1' && b<='5') {
                int idx = (a-'0'-1)*5 + (b-'0'-1);
                if (idx>=0 && idx<25) { out.append(alpha.charAt(idx)); i+=2; if (i<cipher.length() && cipher.charAt(i)==' ') i++; continue; }
            }
        }
        out.append(a); i++;
    }
    return out.toString();
}
private static char polyLatin(char ch) {
    char u = Character.toUpperCase(ch);
    switch (u) {
        case 'Ç': return 'C';
        case 'Ğ': return 'G';
        case 'İ': return 'I';
        case 'Ö': return 'O';
        case 'Ş': return 'S';
        case 'Ü': return 'U';
        case 'J': return 'I';
        default: return (u>='A' && u<='Z') ? u : ch;
    }
}

// ---- Playfair ----
private static String playfairEncrypt(String text, String key) {
    Playfair pf = new Playfair(key);
    String prep = pf.prepareText(text, true);
    StringBuilder out = new StringBuilder(prep.length());
    for (int i=0;i<prep.length(); i+=2) {
        char a = prep.charAt(i), b = prep.charAt(i+1);
        int[] pa = pf.pos(a), pb = pf.pos(b);
        if (pa[0]==pb[0]) { out.append(pf.mat[pa[0]][(pa[1]+1)%5]); out.append(pf.mat[pb[0]][(pb[1]+1)%5]); }
        else if (pa[1]==pb[1]) { out.append(pf.mat[(pa[0]+1)%5][pa[1]]); out.append(pf.mat[(pb[0]+1)%5][pb[1]]); }
        else { out.append(pf.mat[pa[0]][pb[1]]); out.append(pf.mat[pb[0]][pa[1]]); }
    }
    return out.toString();
}
private static String playfairDecrypt(String cipher, String key) {
    Playfair pf = new Playfair(key);
    String prep = pf.prepareText(cipher, false);
    StringBuilder out = new StringBuilder(prep.length());
    for (int i=0;i<prep.length(); i+=2) {
        char a = prep.charAt(i), b = prep.charAt(i+1);
        int[] pa = pf.pos(a), pb = pf.pos(b);
        if (pa[0]==pb[0]) { out.append(pf.mat[pa[0]][(pa[1]+4)%5]); out.append(pf.mat[pb[0]][(pb[1]+4)%5]); }
        else if (pa[1]==pb[1]) { out.append(pf.mat[(pa[0]+4)%5][pa[1]]); out.append(pf.mat[(pb[0]+4)%5][pb[1]]); }
        else { out.append(pf.mat[pa[0]][pb[1]]); out.append(pf.mat[pb[0]][pa[1]]); }
    }
    return out.toString();
}
private static class Playfair {
    final char[][] mat = new char[5][5];
    final int[][] pos = new int[26][2];
    Playfair(String keyRaw) {
        String key = normalizeText(keyRaw==null? "" : keyRaw, true);
        String alpha = "ABCDEFGHIKLMNOPQRSTUVWXYZ";
        StringBuilder seq = new StringBuilder();
        java.util.HashSet<Character> used = new java.util.HashSet<>();
        for (int i=0;i<key.length();i++) {
            char c = polyLatin(key.charAt(i));
            if (c=='J') c='I';
            if (c>='A' && c<='Z' && c!='J' && !used.contains(c)) { used.add(c); seq.append(c); }
        }
        for (int i=0;i<alpha.length();i++) { char c = alpha.charAt(i); if (!used.contains(c)) { used.add(c); seq.append(c); } }
        int k=0; for (int r=0;r<5;r++) for (int c=0;c<5;c++) { mat[r][c]=seq.charAt(k); pos[mat[r][c]-'A'][0]=r; pos[mat[r][c]-'A'][1]=c; k++; }
    }
    int[] pos(char ch) { char u=polyLatin(ch); if (u=='J') u='I'; if (u<'A'||u>'Z') u='X'; return new int[]{ pos[u-'A'][0], pos[u-'A'][1] }; }
    String prepareText(String s, boolean forEnc) {
        StringBuilder t = new StringBuilder();
        for (int i=0;i<s.length();i++) { char u=polyLatin(s.charAt(i)); if (u>='A'&&u<='Z') { if (u=='J') u='I'; t.append(u);} }
        StringBuilder d = new StringBuilder();
        for (int i=0;i<t.length();) {
            char a = t.charAt(i++);
            char b = (i<t.length()) ? t.charAt(i) : 'X';
            if (i>=t.length()) { d.append(a).append('X'); break; }
            if (a==b) { d.append(a).append('X'); }
            else { d.append(a).append(b); i++; }
        }
        if (d.length()%2==1) d.append('X');
        return d.toString();
    }
}

// ---- Pigpen ----
private static String pigpenEncrypt(String text) {
    StringBuilder out = new StringBuilder();
    for (int i=0;i<text.length();i++) {
        char u = Character.toUpperCase(text.charAt(i));
        if (u>='A' && u<='Z') { if (out.length()>0) out.append('|'); out.append("/static/pigpen/").append(u).append(".png"); }
        else { if (out.length()>0) out.append('|'); out.append(text.charAt(i)); }
    }
    return out.toString();
}
private static String pigpenDecrypt(String cipher) {
    StringBuilder out = new StringBuilder();
    String[] tokens = cipher.split("\\|", -1);  // ← iki ters eğik çizgi  
    for (String t : tokens) {
        if (t.startsWith("/static/pigpen/") && t.endsWith(".png") && t.length()==("/static/pigpen/".length()+1+4)) {
            out.append(t.charAt("/static/pigpen/".length()));
        } else out.append(t);
    }
    return out.toString();
}

// ---- Kanonik dağıtıcılar ----
private String encryptDispatchCanonical(String code, String plain, String key) {
    switch (code) {
        case "CAESAR": { int shift=0; try{ shift=Integer.parseInt(key.trim()); }catch(Exception ignored){} return caesarEncrypt(plain, shift); }
        case "VIGENERE": return vigenereEncrypt(plain, key);
        case "SUBSTITUTION": return substitutionEncryptAuto(plain, key);
        case "AFFINE": return affineEncryptAuto(plain, key);
        case "PLAYFAIR": return playfairEncrypt(plain, key);
        case "RAILFENCE": return railFenceEncryptAuto(plain, key);
        case "ROUTE": return routeEncryptAuto(plain, key);
        case "COLUMNAR": return columnarEncrypt(plain, key);
        case "POLYBIUS": return polybiusEncrypt(plain);
        case "PIGPEN": return pigpenEncrypt(plain);
        default: return plain;
    }
}
private String decryptDispatchCanonical(String code, String cipher, String key) {
    switch (code) {
        case "CAESAR": { int shift=0; try{ shift=Integer.parseInt(key.trim()); }catch(Exception ignored){} return caesarDecrypt(cipher, shift); }
        case "VIGENERE": return vigenereDecrypt(cipher, key);
        case "SUBSTITUTION": return substitutionDecryptAuto(cipher, key);
        case "AFFINE": return affineDecryptAuto(cipher, key);
        case "PLAYFAIR": return playfairDecrypt(cipher, key);
        case "RAILFENCE": return railFenceDecryptAuto(cipher, key);
        case "ROUTE": return routeDecryptAuto(cipher, key);
        case "COLUMNAR": return columnarDecrypt(cipher, key);
        case "POLYBIUS": return polybiusDecrypt(cipher);
        case "PIGPEN": return pigpenDecrypt(cipher);
        default: return cipher;
    }
}

}