package cryptoo;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;
import cryptoo.crypto.api.TextCipher;
import cryptoo.crypto.registry.AlgorithmRegistry;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays; // used in helper
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Tüm şifreleme algoritmalarını toplayan yardımcı sınıf.
 *
 * - Klasik şifreler: CAESAR, VIGENERE, SUBSTITUTION, AFFINE,
 * PLAYFAIR, RAILFENCE, ROUTE, COLUMNAR, POLYBIUS, PIGPEN
 * - Modern: AES_GCM (PBKDF2 / Session key), DES
 *
 * Not:
 * - encrypt/decrypt fonksiyonları "kanonik metni" üretir/alır.
 * - Client tarafında bu metin ayrıca Base64 ile sarılır (wire-level için).
 */
public final class CryptoUtils {

    // ---- Algoritma kodları (wire-level'da da bunlar kullanılıyor) ----
    public static final String ALGO_NONE = "NONE";
    public static final String ALGO_CAESAR = "CAESAR";
    public static final String ALGO_VIGENERE = "VIGENERE";
    public static final String ALGO_SUBST = "SUBSTITUTION";
    public static final String ALGO_AFFINE = "AFFINE";
    public static final String ALGO_PLAYFAIR = "PLAYFAIR";
    public static final String ALGO_RAILFENCE = "RAILFENCE";
    public static final String ALGO_ROUTE = "ROUTE";
    public static final String ALGO_COLUMNAR = "COLUMNAR";
    public static final String ALGO_POLYBIUS = "POLYBIUS";
    public static final String ALGO_PIGPEN = "PIGPEN";
    public static final String ALGO_AES_GCM = "AES_GCM";
    public static final String ALGO_DES = "DES";
    public static final String ALGO_HILL = "HILL";
    public static final String ALGO_3DES = "3DES";
    public static final String ALGO_BLOWFISH = "BLOWFISH";
    public static final String ALGO_GOST = "GOST";
    public static final String ALGO_FEISTEL = "FEISTEL"; // toy
    public static final String ALGO_SPN = "SPN"; // toy
    public static final String ALGO_AES_GCM_BC = "AES_GCM_BC";
    public static final String ALGO_DES_BC = "DES_BC";

    // RSA & Hybrid Constants
    public static final String ALGO_RSA_PUB = "RSA_PUB";
    public static final String ALGO_RSA_PUBREQ = "RSA_PUBREQ";
    public static final String ALGO_AES_GCM_RSA = "AES_GCM_RSA";
    public static final String ALGO_AES_GCM_BC_RSA = "AES_GCM_BC_RSA";
    public static final String ALGO_DES_RSA = "DES_RSA";
    public static final String ALGO_DES_BC_RSA = "DES_BC_RSA";

    // ---- Ortak sabitler ----
    private static final String TR_ALPHABET = "ABCÇDEFGĞHIİJKLMNOÖPRSŞTUÜVYZ";
    private static final SecureRandom RNG = new SecureRandom();
    private static final byte[] FIXED_SALT = "SecureChatFixedSalt".getBytes(StandardCharsets.UTF_8);

    static {
        // BouncyCastle provider'ı ekle (DES/AES için şart değil ama ileride lazım
        // olabilir)
        try {
            BCConfig.init();
        } catch (Throwable t) {
            System.err.println("Warning: BC provider not available (CryptoUtils): " + t.getMessage());
        }
        AlgorithmRegistry.registerDefaults();
    }

    public static boolean isBcAvailable() {
        try {
            // BC jar var mı?
            Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider");

            // Provider'ı eklemeyi dene (idempotent olmalı)
            try {
                BCConfig.init();
            } catch (Throwable ignored) {
            }

            return java.security.Security.getProvider("BC") != null;
        } catch (Throwable t) {
            return false;
        }
    }

    private CryptoUtils() {
    }

    // =================================================================
    // GENEL ENCRYPT / DECRYPT
    // =================================================================

    public static String encrypt(String algoCode, String plain, String key) throws Exception {
        if (algoCode == null || ALGO_NONE.equals(algoCode)) {
            return plain;
        }

        // 1. Registry Lookup
        TextCipher cipher = AlgorithmRegistry.get(algoCode);
        if (cipher != null) {
            return cipher.encrypt(plain, key);
        }

        // 2. Legacy Fallback
        if (plain == null)
            plain = "";

        switch (algoCode) {
            // case ALGO_SUBST: handled by registry
            // case ALGO_AFFINE: handled by registry
            case ALGO_PLAYFAIR:
                return playfairEncrypt(plain, key);
            // case ALGO_RAILFENCE: handled by registry
            case ALGO_ROUTE:
                return routeEncryptAuto(plain, key);
            case ALGO_COLUMNAR:
                return columnarEncrypt(plain, key);
            // case ALGO_POLYBIUS: handled by registry
            case ALGO_PIGPEN:
                return pigpenEncrypt(plain);
            case ALGO_HILL:
                return hillEncryptAuto(plain, key);

            case ALGO_FEISTEL:
                return feistelToyEncrypt(plain, key);
            case ALGO_SPN:
                return spnToyEncrypt(plain, key);
            default:
                return plain;
        }
    }

    public static String decrypt(String algoCode, String cipherText, String key) throws Exception {
        if (algoCode == null || ALGO_NONE.equals(algoCode)) {
            return cipherText;
        }

        // 1. Registry Lookup
        TextCipher cipher = AlgorithmRegistry.get(algoCode);
        if (cipher != null) {
            return cipher.decrypt(cipherText, key);
        }

        // 2. Legacy Fallback
        if (cipherText == null)
            cipherText = "";

        switch (algoCode) {
            // case ALGO_SUBST: handled by registry
            // case ALGO_AFFINE: handled by registry
            case ALGO_PLAYFAIR:
                return playfairDecrypt(cipherText, key);
            // case ALGO_RAILFENCE: handled by registry
            case ALGO_ROUTE:
                return routeDecryptAuto(cipherText, key);
            case ALGO_COLUMNAR:
                return columnarDecrypt(cipherText, key);
            // case ALGO_POLYBIUS: handled by registry
            case ALGO_PIGPEN:
                return pigpenDecrypt(cipherText);
            case ALGO_HILL:
                return hillDecryptAuto(cipherText, key);

            case ALGO_FEISTEL:
                return feistelToyDecrypt(cipherText, key);
            case ALGO_SPN:
                return spnToyDecrypt(cipherText, key);
            default:
                return cipherText;
        }
    }

    private static int parseIntSafe(String s, int def) {
        try {
            if (s == null)
                return def;
            return Integer.parseInt(s.trim());
        } catch (Exception e) {
            return def;
        }
    }

    // =================================================================
    // TÜRK ALFABESİ YARDIMCILARI
    // =================================================================

    private static boolean isTrLetter(char ch) {
        char u = Character.toUpperCase(ch);
        return TR_ALPHABET.indexOf(u) >= 0;
    }

    private static char safeChar(char ch) {
        if (isTrLetter(ch))
            return Character.toUpperCase(ch);
        return ch;
    }

    private static String normalizeText(String s, boolean lettersOnly) {
        if (s == null)
            return "";
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = safeChar(s.charAt(i));
            if (lettersOnly) {
                if (isTrLetter(c))
                    sb.append(c);
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    private static int alphaIndex(char u) {
        return TR_ALPHABET.indexOf(u);
    }

    // =================================================================
    // AFFINE
    // =================================================================

    private static String affineEncryptAuto(String text, String key) {
        int[] ab = parseAB(key);
        return affineEncrypt(text, ab[0], ab[1]);
    }

    private static String affineDecryptAuto(String cipher, String key) {
        int[] ab = parseAB(key);
        return affineDecrypt(cipher, ab[0], ab[1]);
    }

    private static int[] parseAB(String key) {
        int a = 1, b = 0;
        if (key != null) {
            String[] t = key.split("[,; ]+");
            try {
                if (t.length > 0)
                    a = Integer.parseInt(t[0].trim());
            } catch (Exception ignored) {
            }
            try {
                if (t.length > 1)
                    b = Integer.parseInt(t[1].trim());
            } catch (Exception ignored) {
            }
        }
        return new int[] { a, b };
    }

    private static int egcdInv(int a, int m) {
        int t = 0, newt = 1, r = m, newr = a % m;
        if (newr < 0)
            newr += m;
        while (newr != 0) {
            int q = r / newr;
            int tmp = t - q * newt;
            t = newt;
            newt = tmp;
            tmp = r - q * newr;
            r = newr;
            newr = tmp;
        }
        if (r > 1)
            return 1;
        if (t < 0)
            t += m;
        return t;
    }

    private static String affineEncrypt(String text, int a, int b) {
        int n = TR_ALPHABET.length();
        StringBuilder out = new StringBuilder(text.length());
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            char u = safeChar(c);
            int idx = TR_ALPHABET.indexOf(u);
            if (idx >= 0) {
                int ni = (a * idx + b) % n;
                if (ni < 0)
                    ni += n;
                out.append(TR_ALPHABET.charAt(ni));
            } else
                out.append(c);
        }
        return out.toString();
    }

    private static String affineDecrypt(String cipher, int a, int b) {
        int n = TR_ALPHABET.length();
        int ai = egcdInv(a, n);
        StringBuilder out = new StringBuilder(cipher.length());
        for (int i = 0; i < cipher.length(); i++) {
            char c = cipher.charAt(i);
            char u = safeChar(c);
            int idx = TR_ALPHABET.indexOf(u);
            if (idx >= 0) {
                int ni = (ai * (idx - b)) % n;
                if (ni < 0)
                    ni += n;
                out.append(TR_ALPHABET.charAt(ni));
            } else
                out.append(c);
        }
        return out.toString();
    }

    // =================================================================
    // RAIL FENCE
    // =================================================================

    private static String railFenceEncryptAuto(String text, String key) {
        int rails = 2;
        try {
            rails = Integer.parseInt(key.trim());
        } catch (Exception ignored) {
        }
        return railFenceEncrypt(text, rails);
    }

    private static String railFenceEncrypt(String text, int rails) {
        if (rails <= 1)
            return text;
        StringBuilder[] rows = new StringBuilder[rails];
        for (int i = 0; i < rails; i++)
            rows[i] = new StringBuilder();
        int r = 0, dir = 1;
        for (int i = 0; i < text.length(); i++) {
            rows[r].append(text.charAt(i));
            r += dir;
            if (r == rails - 1)
                dir = -1;
            else if (r == 0)
                dir = 1;
        }
        StringBuilder out = new StringBuilder(text.length());
        for (int i = 0; i < rails; i++)
            out.append(rows[i]);
        return out.toString();
    }

    private static String railFenceDecrypt(String cipher, int rails) {
        if (rails <= 1)
            return cipher;
        int len = cipher.length();
        boolean[][] mark = new boolean[rails][len];
        int r = 0, dir = 1;
        for (int j = 0; j < len; j++) {
            mark[r][j] = true;
            r += dir;
            if (r == rails - 1)
                dir = -1;
            else if (r == 0)
                dir = 1;
        }
        char[][] grid = new char[rails][len];
        int idx = 0;
        for (int i = 0; i < rails; i++) {
            for (int j = 0; j < len; j++) {
                if (mark[i][j])
                    grid[i][j] = cipher.charAt(idx++);
            }
        }
        StringBuilder res = new StringBuilder(len);
        r = 0;
        dir = 1;
        for (int j = 0; j < len; j++) {
            res.append(grid[r][j]);
            r += dir;
            if (r == rails - 1)
                dir = -1;
            else if (r == 0)
                dir = 1;
        }
        return res.toString();
    }

    // =================================================================
    // ROUTE (SPIRAL)
    // =================================================================

    private static String routeEncryptAuto(String text, String key) {
        int cols = 3;
        boolean cw = true;
        if (key != null && !key.isEmpty()) {
            String k = key.toLowerCase();
            try {
                cols = Integer.parseInt(k.replaceAll("[^0-9]", ""));
            } catch (Exception ignored) {
            }
            if (k.contains("ccw") || k.contains("counter"))
                cw = false;
        }
        return routeEncrypt(text, cols, cw);
    }

    private static String routeDecryptAuto(String cipher, String key) {
        int cols = 3;
        boolean cw = true;
        if (key != null && !key.isEmpty()) {
            String k = key.toLowerCase();
            try {
                cols = Integer.parseInt(k.replaceAll("[^0-9]", ""));
            } catch (Exception ignored) {
            }
            if (k.contains("ccw") || k.contains("counter"))
                cw = false;
        }
        return routeDecrypt(cipher, cols, cw);
    }

    private static String routeEncrypt(String text, int cols, boolean clockwise) {
        if (cols <= 1)
            return text;
        int len = text.length();
        int rows = (len + cols - 1) / cols;
        char[][] grid = new char[rows][cols];
        int idx = 0;
        for (int i = 0; i < rows; i++)
            for (int j = 0; j < cols; j++)
                grid[i][j] = (idx < len) ? text.charAt(idx++) : 0;

        StringBuilder out = new StringBuilder(len);
        int top = 0, bottom = rows - 1, left = 0, right = cols - 1, taken = 0;
        while (top <= bottom && left <= right && taken < len) {
            if (clockwise) {
                for (int j = left; j <= right && taken < len; j++) {
                    int pos = top * cols + j;
                    if (pos < len) {
                        out.append(grid[top][j]);
                        taken++;
                    }
                }
                top++;
                for (int i = top; i <= bottom && taken < len; i++) {
                    int pos = i * cols + right;
                    if (pos < len) {
                        out.append(grid[i][right]);
                        taken++;
                    }
                }
                right--;
                if (top <= bottom) {
                    for (int j = right; j >= left && taken < len; j--) {
                        int pos = bottom * cols + j;
                        if (pos < len) {
                            out.append(grid[bottom][j]);
                            taken++;
                        }
                    }
                    bottom--;
                }
                if (left <= right) {
                    for (int i = bottom; i >= top && taken < len; i--) {
                        int pos = i * cols + left;
                        if (pos < len) {
                            out.append(grid[i][left]);
                            taken++;
                        }
                    }
                    left++;
                }
            } else {
                for (int i = top; i <= bottom && taken < len; i++) {
                    int pos = i * cols + left;
                    if (pos < len) {
                        out.append(grid[i][left]);
                        taken++;
                    }
                }
                left++;
                for (int j = left; j <= right && taken < len; j++) {
                    int pos = bottom * cols + j;
                    if (pos < len) {
                        out.append(grid[bottom][j]);
                        taken++;
                    }
                }
                bottom--;
                if (left <= right) {
                    for (int i = bottom; i >= top && taken < len; i--) {
                        int pos = i * cols + right;
                        if (pos < len) {
                            out.append(grid[i][right]);
                            taken++;
                        }
                    }
                    right--;
                }
                if (top <= bottom) {
                    for (int j = right; j >= left && taken < len; j--) {
                        int pos = top * cols + j;
                        if (pos < len) {
                            out.append(grid[top][j]);
                            taken++;
                        }
                    }
                    top++;
                }
            }
        }
        return out.toString();
    }

    private static String routeDecrypt(String cipher, int cols, boolean clockwise) {
        if (cols <= 1)
            return cipher;
        int len = cipher.length();
        int rows = (len + cols - 1) / cols;
        char[][] grid = new char[rows][cols];
        int top = 0, bottom = rows - 1, left = 0, right = cols - 1, idx = 0;

        while (top <= bottom && left <= right && idx < len) {
            if (clockwise) {
                for (int j = left; j <= right && idx < len; j++) {
                    int pos = top * cols + j;
                    if (pos < len)
                        grid[top][j] = cipher.charAt(idx++);
                }
                top++;
                for (int i = top; i <= bottom && idx < len; i++) {
                    int pos = i * cols + right;
                    if (pos < len)
                        grid[i][right] = cipher.charAt(idx++);
                }
                right--;
                if (top <= bottom) {
                    for (int j = right; j >= left && idx < len; j--) {
                        int pos = bottom * cols + j;
                        if (pos < len)
                            grid[bottom][j] = cipher.charAt(idx++);
                    }
                    bottom--;
                }
                if (left <= right) {
                    for (int i = bottom; i >= top && idx < len; i--) {
                        int pos = i * cols + left;
                        if (pos < len)
                            grid[i][left] = cipher.charAt(idx++);
                    }
                    left++;
                }
            } else {
                for (int i = top; i <= bottom && idx < len; i++) {
                    int pos = i * cols + left;
                    if (pos < len)
                        grid[i][left] = cipher.charAt(idx++);
                }
                left++;
                for (int j = left; j <= right && idx < len; j++) {
                    int pos = bottom * cols + j;
                    if (pos < len)
                        grid[bottom][j] = cipher.charAt(idx++);
                }
                bottom--;
                if (left <= right) {
                    for (int i = bottom; i >= top && idx < len; i--) {
                        int pos = i * cols + right;
                        if (pos < len)
                            grid[i][right] = cipher.charAt(idx++);
                    }
                    right--;
                }
                if (top <= bottom) {
                    for (int j = right; j >= left && idx < len; j--) {
                        int pos = top * cols + j;
                        if (pos < len)
                            grid[top][j] = cipher.charAt(idx++);
                    }
                    top++;
                }
            }
        }

        StringBuilder out = new StringBuilder(len);
        int count = 0;
        for (int i = 0; i < rows; i++)
            for (int j = 0; j < cols; j++) {
                if (count < len)
                    out.append(grid[i][j]);
                count++;
            }
        return out.toString();
    }

    // =================================================================
    // COLUMNAR TRANSPOSITION
    // =================================================================

    private static String columnarEncrypt(String text, String key) {
        if (key == null || key.isEmpty())
            return text;
        String k = normalizeText(key, true);
        if (k.isEmpty())
            return text;
        int cols = k.length(), len = text.length(), rows = (len + cols - 1) / cols;
        int[] order = columnOrder(k);
        StringBuilder out = new StringBuilder(len);
        for (int oi = 0; oi < cols; oi++) {
            int col = order[oi];
            for (int r = 0; r < rows; r++) {
                int idx = r * cols + col;
                if (idx < len)
                    out.append(text.charAt(idx));
            }
        }
        return out.toString();
    }

    private static String columnarDecrypt(String cipher, String key) {
        if (key == null || key.isEmpty())
            return cipher;
        String k = normalizeText(key, true);
        if (k.isEmpty())
            return cipher;
        int cols = k.length(), len = cipher.length(), rows = (len + cols - 1) / cols, rem = len % cols;
        int[] order = columnOrder(k);
        int[] colHeights = new int[cols];
        for (int c = 0; c < cols; c++)
            colHeights[c] = rows - ((rem != 0 && c >= rem) ? 1 : 0);
        char[][] grid = new char[rows][cols];
        int idx = 0;
        for (int oi = 0; oi < cols; oi++) {
            int col = order[oi], h = colHeights[col];
            for (int r = 0; r < h; r++)
                grid[r][col] = cipher.charAt(idx++);
        }
        StringBuilder out = new StringBuilder(len);
        for (int r = 0; r < rows; r++)
            for (int c = 0; c < cols; c++) {
                int pos = r * cols + c;
                if (pos < len)
                    out.append(grid[r][c]);
            }
        return out.toString();
    }

    private static int[] columnOrder(String k) {
        int n = k.length();
        Integer[] idx = new Integer[n];
        for (int i = 0; i < n; i++)
            idx[i] = i;
        java.util.Arrays.sort(idx, (a, b) -> {
            char ca = k.charAt(a), cb = k.charAt(b);
            if (ca == cb)
                return Integer.compare(a, b);
            return Character.compare(ca, cb);
        });
        int[] order = new int[n];
        for (int i = 0; i < n; i++)
            order[i] = idx[i];
        return order;
    }

    // =================================================================
    // POLYBIUS (5x5)
    // =================================================================

    private static char polyLatin(char ch) {
        char u = Character.toUpperCase(ch);
        switch (u) {
            case 'Ç':
                return 'C';
            case 'Ğ':
                return 'G';
            case 'İ':
                return 'I';
            case 'Ö':
                return 'O';
            case 'Ş':
                return 'S';
            case 'Ü':
                return 'U';
            case 'J':
                return 'I'; // I/J birleşik
            default:
                return (u >= 'A' && u <= 'Z') ? u : ch;
        }
    }

    // =================================================================
    // PLAYFAIR
    // =================================================================

    private static String playfairEncrypt(String text, String key) {
        Playfair pf = new Playfair(key);
        String prep = pf.prepareText(text, true);
        StringBuilder out = new StringBuilder(prep.length());
        for (int i = 0; i < prep.length(); i += 2) {
            char a = prep.charAt(i), b = prep.charAt(i + 1);
            int[] pa = pf.pos(a), pb = pf.pos(b);
            if (pa[0] == pb[0]) {
                out.append(pf.mat[pa[0]][(pa[1] + 1) % 5]);
                out.append(pf.mat[pb[0]][(pb[1] + 1) % 5]);
            } else if (pa[1] == pb[1]) {
                out.append(pf.mat[(pa[0] + 1) % 5][pa[1]]);
                out.append(pf.mat[(pb[0] + 1) % 5][pb[1]]);
            } else {
                out.append(pf.mat[pa[0]][pb[1]]);
                out.append(pf.mat[pb[0]][pa[1]]);
            }
        }
        return out.toString();
    }

    private static String playfairDecrypt(String cipher, String key) {
        Playfair pf = new Playfair(key);
        String prep = pf.prepareText(cipher, false);
        StringBuilder out = new StringBuilder(prep.length());
        for (int i = 0; i < prep.length(); i += 2) {
            char a = prep.charAt(i), b = prep.charAt(i + 1);
            int[] pa = pf.pos(a), pb = pf.pos(b);
            if (pa[0] == pb[0]) {
                out.append(pf.mat[pa[0]][(pa[1] + 4) % 5]);
                out.append(pf.mat[pb[0]][(pb[1] + 4) % 5]);
            } else if (pa[1] == pb[1]) {
                out.append(pf.mat[(pa[0] + 4) % 5][pa[1]]);
                out.append(pf.mat[(pb[0] + 4) % 5][pb[1]]);
            } else {
                out.append(pf.mat[pa[0]][pb[1]]);
                out.append(pf.mat[pb[0]][pa[1]]);
            }
        }
        return out.toString();
    }

    private static class Playfair {
        final char[][] mat = new char[5][5];
        final int[][] pos = new int[26][2];

        Playfair(String keyRaw) {
            String key = normalizeText(keyRaw == null ? "" : keyRaw, true);
            String alpha = "ABCDEFGHIKLMNOPQRSTUVWXYZ"; // J yok
            StringBuilder seq = new StringBuilder();
            java.util.HashSet<Character> used = new java.util.HashSet<>();
            for (int i = 0; i < key.length(); i++) {
                char c = polyLatin(key.charAt(i));
                if (c == 'J')
                    c = 'I';
                if (c >= 'A' && c <= 'Z' && c != 'J' && !used.contains(c)) {
                    used.add(c);
                    seq.append(c);
                }
            }
            for (int i = 0; i < alpha.length(); i++) {
                char c = alpha.charAt(i);
                if (!used.contains(c)) {
                    used.add(c);
                    seq.append(c);
                }
            }
            int k = 0;
            for (int r = 0; r < 5; r++) {
                for (int c = 0; c < 5; c++) {
                    mat[r][c] = seq.charAt(k);
                    pos[mat[r][c] - 'A'][0] = r;
                    pos[mat[r][c] - 'A'][1] = c;
                    k++;
                }
            }
        }

        int[] pos(char ch) {
            char u = polyLatin(ch);
            if (u == 'J')
                u = 'I';
            if (u < 'A' || u > 'Z')
                u = 'X';
            return new int[] { pos[u - 'A'][0], pos[u - 'A'][1] };
        }

        String prepareText(String s, boolean forEnc) {
            StringBuilder t = new StringBuilder();
            for (int i = 0; i < s.length(); i++) {
                char u = polyLatin(s.charAt(i));
                if (u >= 'A' && u <= 'Z') {
                    if (u == 'J')
                        u = 'I';
                    t.append(u);
                }
            }
            StringBuilder d = new StringBuilder();
            for (int i = 0; i < t.length();) {
                char a = t.charAt(i++);
                char b = (i < t.length()) ? t.charAt(i) : 'X';
                if (i >= t.length()) {
                    d.append(a).append('X');
                    break;
                }
                if (a == b) {
                    d.append(a).append('X');
                } else {
                    d.append(a).append(b);
                    i++;
                }
            }
            if (d.length() % 2 == 1)
                d.append('X');
            return d.toString();
        }
    }

    // =================================================================
    // PIGPEN
    // =================================================================

    private static String pigpenEncrypt(String text) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < text.length(); i++) {
            char u = Character.toUpperCase(text.charAt(i));
            if (u >= 'A' && u <= 'Z') {
                if (out.length() > 0)
                    out.append('|');
                out.append("/static/pigpen/").append(u).append(".png");
            } else {
                if (out.length() > 0)
                    out.append('|');
                out.append(text.charAt(i));
            }
        }
        return out.toString();
    }

    private static String pigpenDecrypt(String cipher) {
        StringBuilder out = new StringBuilder();
        String[] tokens = cipher.split("\\|", -1);
        for (String t : tokens) {
            if (t.startsWith("/static/pigpen/") && t.endsWith(".png")
                    && t.length() == ("/static/pigpen/".length() + 1 + 4)) {
                out.append(t.charAt("/static/pigpen/".length()));
            } else
                out.append(t);
        }
        return out.toString();
    }

    // ======================= HILL (2x2 / 3x3) =======================
    private static String hillEncryptAuto(String text, String key) {
        HillKey hk = HillKey.parse(key);
        return hillProcess(text, hk, true);
    }

    private static String hillDecryptAuto(String cipher, String key) {
        HillKey hk = HillKey.parse(key).inverse();
        return hillProcess(cipher, hk, true);
    }

    private static String hillProcess(String s, HillKey hk, boolean keepNonLetters) {
        // TR alfabetik çalıştırmak istersen: TR_ALPHABET kullanır.
        // Hill klasik olarak 26 ile çalışır; burada TR_ALPHABET (29) ile çalışıyoruz.
        final int mod = TR_ALPHABET.length();

        StringBuilder out = new StringBuilder();
        StringBuilder buf = new StringBuilder();

        for (int i = 0; i < s.length(); i++) {
            char ch = safeChar(s.charAt(i));
            if (isTrLetter(ch))
                buf.append(ch);
            else {
                if (keepNonLetters) {
                    out.append(hillBlockTransform(buf.toString(), hk, mod));
                    buf.setLength(0);
                    out.append(s.charAt(i));
                }
            }
        }
        out.append(hillBlockTransform(buf.toString(), hk, mod));
        return out.toString();
    }

    private static String hillBlockTransform(String letters, HillKey hk, int mod) {
        if (letters.isEmpty())
            return "";
        int n = hk.n;
        StringBuilder res = new StringBuilder();

        int idx = 0;
        while (idx < letters.length()) {
            int[] v = new int[n];
            for (int i = 0; i < n; i++) {
                if (idx + i < letters.length()) {
                    v[i] = alphaIndex(letters.charAt(idx + i));
                } else {
                    v[i] = alphaIndex('X'); // pad
                }
            }
            int[] w = hk.mul(v, mod);
            for (int i = 0; i < n; i++) {
                res.append(TR_ALPHABET.charAt(w[i]));
            }
            idx += n;
        }
        return res.toString();
    }

    private static class HillKey {
        final int n;
        final int[][] m;

        HillKey(int n, int[][] m) {
            this.n = n;
            this.m = m;
        }

        static HillKey parse(String key) {
            if (key == null)
                throw new IllegalArgumentException("Hill key boş olamaz");
            String[] parts = key.split("[,;\\s]+");
            if (parts.length == 4) {
                int[][] m = new int[][] {
                        { Integer.parseInt(parts[0]), Integer.parseInt(parts[1]) },
                        { Integer.parseInt(parts[2]), Integer.parseInt(parts[3]) }
                };
                return new HillKey(2, m);
            } else if (parts.length == 9) {
                int[][] m = new int[][] {
                        { Integer.parseInt(parts[0]), Integer.parseInt(parts[1]), Integer.parseInt(parts[2]) },
                        { Integer.parseInt(parts[3]), Integer.parseInt(parts[4]), Integer.parseInt(parts[5]) },
                        { Integer.parseInt(parts[6]), Integer.parseInt(parts[7]), Integer.parseInt(parts[8]) }
                };
                return new HillKey(3, m);
            }
            throw new IllegalArgumentException("Hill key formatı: 2x2 için 4 sayı, 3x3 için 9 sayı olmalı.");
        }

        int[] mul(int[] v, int mod) {
            int[] r = new int[n];
            for (int i = 0; i < n; i++) {
                long sum = 0;
                for (int j = 0; j < n; j++)
                    sum += (long) m[i][j] * v[j];
                int x = (int) (sum % mod);
                if (x < 0)
                    x += mod;
                r[i] = x;
            }
            return r;
        }

        HillKey inverse() {
            // 2x2 ve 3x3 için modüler ters (basit eğitim implementasyonu)
            int mod = TR_ALPHABET.length();
            if (n == 2)
                return inverse2(mod);
            if (n == 3)
                return inverse3(mod);
            throw new IllegalStateException("Hill inverse sadece 2x2/3x3 destekli.");
        }

        private HillKey inverse2(int mod) {
            int a = m[0][0], b = m[0][1], c = m[1][0], d = m[1][1];
            int det = (a * d - b * c) % mod;
            if (det < 0)
                det += mod;
            int detInv = modInverse(det, mod);
            int[][] inv = new int[][] {
                    { (d * detInv) % mod, ((-b) * detInv) % mod },
                    { ((-c) * detInv) % mod, (a * detInv) % mod }
            };
            for (int i = 0; i < 2; i++)
                for (int j = 0; j < 2; j++) {
                    inv[i][j] %= mod;
                    if (inv[i][j] < 0)
                        inv[i][j] += mod;
                }
            return new HillKey(2, inv);
        }

        private HillKey inverse3(int mod) {
            int[][] A = m;
            int det = A[0][0] * (A[1][1] * A[2][2] - A[1][2] * A[2][1]) -
                    A[0][1] * (A[1][0] * A[2][2] - A[1][2] * A[2][0]) +
                    A[0][2] * (A[1][0] * A[2][1] - A[1][1] * A[2][0]);
            det %= mod;
            if (det < 0)
                det += mod;
            int detInv = modInverse(det, mod);

            int[][] adj = new int[3][3];
            adj[0][0] = (A[1][1] * A[2][2] - A[1][2] * A[2][1]);
            adj[0][1] = -(A[1][0] * A[2][2] - A[1][2] * A[2][0]);
            adj[0][2] = (A[1][0] * A[2][1] - A[1][1] * A[2][0]);

            adj[1][0] = -(A[0][1] * A[2][2] - A[0][2] * A[2][1]);
            adj[1][1] = (A[0][0] * A[2][2] - A[0][2] * A[2][0]);
            adj[1][2] = -(A[0][0] * A[2][1] - A[0][1] * A[2][0]);

            adj[2][0] = (A[0][1] * A[1][2] - A[0][2] * A[1][1]);
            adj[2][1] = -(A[0][0] * A[1][2] - A[0][2] * A[1][0]);
            adj[2][2] = (A[0][0] * A[1][1] - A[0][1] * A[1][0]);

            // transpose(adj) * detInv
            int[][] inv = new int[3][3];
            for (int i = 0; i < 3; i++)
                for (int j = 0; j < 3; j++) {
                    long x = (long) adj[j][i] * detInv;
                    int v = (int) (x % mod);
                    if (v < 0)
                        v += mod;
                    inv[i][j] = v;
                }
            return new HillKey(3, inv);
        }
    }

    private static int modInverse(int a, int m) {
        // a^-1 mod m
        int t = 0, newt = 1, r = m, newr = a % m;
        if (newr < 0)
            newr += m;
        while (newr != 0) {
            int q = r / newr;
            int tmp = t - q * newt;
            t = newt;
            newt = tmp;
            tmp = r - q * newr;
            r = newr;
            newr = tmp;
        }
        if (r != 1)
            throw new IllegalArgumentException("Hill key determinant invertible değil (mod " + m + ")");
        if (t < 0)
            t += m;
        return t;
    }

    // ======================= FEISTEL (TOY) =======================
    // Kanonik format: base64(bytes)
    // ======================= FEISTEL (TOY) =======================
    // Kanonik format: base64(bytes)
    private static String feistelToyEncrypt(String plain, String key) {
        byte[] data = plain.getBytes(StandardCharsets.UTF_8);
        byte[] out = feistelToy(data, key, true);
        return Base64.getEncoder().encodeToString(out);
    }

    private static String feistelToyDecrypt(String canonical, String key) {
        try {
            byte[] ct = Base64.getDecoder().decode(canonical);
            byte[] out = feistelToy(ct, key, false);

            // padding nedeniyle eklenen trailing 0'ları güvenli kırp
            int end = out.length;
            while (end > 0 && out[end - 1] == 0)
                end--;
            return new String(out, 0, end, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            // Legacy Fallback (Non-Base64 input)
            return feistelToyDecryptLegacy(canonical, key);
        }
    }

    private static String feistelToyDecryptLegacy(String cipherText, String key) {
        byte[] data = cipherText.getBytes(StandardCharsets.UTF_8);
        byte[] k = (key == null ? "k" : key).getBytes(StandardCharsets.UTF_8);
        // Legacy padding shim (if needed, but old code just did this:)
        byte[] buf = java.util.Arrays.copyOf(data, data.length + (data.length % 2));

        for (int round = 0; round < 16; round++) {
            int r = (15 - round);
            // Old broken logic: f uses L (which is buf[i]), then XORs R into buf[i], then
            // sets buf[i+1] to L
            for (int i = 0; i + 1 < buf.length; i += 2) {
                byte L = buf[i];
                byte R = buf[i + 1];
                byte f = (byte) ((L ^ k[r % k.length]) + r);
                buf[i] = (byte) (R ^ f);
                buf[i + 1] = L;
            }
        }
        return new String(buf, StandardCharsets.UTF_8).trim();
    }

    private static byte[] feistelToy(byte[] input, String key, boolean enc) {
        byte[] k = (key == null || key.isEmpty() ? "k" : key).getBytes(StandardCharsets.UTF_8);

        // even-length pad (1 byte) — decrypt’te trailing 0 kırpıyoruz
        byte[] buf = java.util.Arrays.copyOf(input, input.length + (input.length % 2));

        for (int round = 0; round < 16; round++) {
            int r = enc ? round : (15 - round);
            int kb = k[r % k.length] & 0xFF;

            for (int i = 0; i + 1 < buf.length; i += 2) {
                int L = buf[i] & 0xFF;
                int R = buf[i + 1] & 0xFF;

                if (enc) {
                    // L' = R, R' = L ^ F(R)
                    int f = ((R ^ kb) + r) & 0xFF;
                    int newL = R;
                    int newR = (L ^ f) & 0xFF;
                    buf[i] = (byte) newL;
                    buf[i + 1] = (byte) newR;
                } else {
                    // decrypt: R_prev = L_cur, L_prev = R_cur ^ F(L_cur)
                    int Rprev = L;
                    int f = ((Rprev ^ kb) + r) & 0xFF;
                    int Lprev = (R ^ f) & 0xFF;
                    buf[i] = (byte) Lprev;
                    buf[i + 1] = (byte) Rprev;
                }
            }
        }
        return buf;
    }

    // ======================= SPN (TOY) =======================
    // ======================= SPN (TOY) =======================
    private static String spnToyEncrypt(String plain, String key) {
        byte[] in = plain.getBytes(StandardCharsets.UTF_8);
        return Base64.getEncoder().encodeToString(spnToy(in, key, true));
    }

    private static String spnToyDecrypt(String canonical, String key) {
        try {
            byte[] ct = Base64.getDecoder().decode(canonical);
            return new String(spnToy(ct, key, false), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            // Legacy Fallback
            return spnToyDecryptLegacy(canonical, key);
        }
    }

    private static String spnToyDecryptLegacy(String cipherText, String key) {
        byte[] out = cipherText.getBytes(StandardCharsets.UTF_8);
        byte[] k = (key == null ? "k" : key).getBytes(StandardCharsets.UTF_8);
        int[] sbox = { 6, 4, 12, 5, 0, 7, 2, 14, 1, 15, 3, 13, 8, 10, 9, 11 };
        int[] inv = new int[16];
        for (int i = 0; i < 16; i++)
            inv[sbox[i]] = i;

        for (int round = 0; round < 8; round++) {
            int r = (7 - round);
            for (int i = 0; i < out.length; i++) {
                int b = out[i] & 0xFF;
                // Old broken decrypt order: invPERM -> invSBOX -> XOR
                // BUT old code implementation was:
                // 1. invPERM (rotr3)
                // 2. invSBOX
                // 3. XOR
                // This logic is actually what we kept as CORRECT in the new version?
                // Wait, if I fixed it in step 214, I should check what I changed.
                // In Step 214 diff:
                // Old:
                // inv perm
                // inv sbox
                // xor
                // New:
                // inv perm
                // inv sbox
                // xor
                // Wait, the logic block looks identical in Step 214 diff for the decrypt case?
                // "New: // invPERM -> invSBOX -> XOR"
                // The main change in Step 214 for SPN was mostly adding Base64 wrapper and
                // standardizing loop/comments?
                // Or did I change the bit shifts?
                // Old: b = (((b >>> 3) | (b << 5)) & 0xFF);
                // New: b = (((b >>> 3) | (b << 5)) & 0xFF);
                // It seems SPN logic might have been symmetric enough or I didn't change it
                // significantly other than cleanup?
                // User said "Fixed logic in feistelToy and spnToy to ensure they are
                // mathematically reversible".
                // If I assume the *old* logic was also trying to be reversible but failed, I
                // should replicate exactly what was there.
                // The snippet from Step 107 view for SPN Decrypt:
                // b = (((b >>> 3) | (b << 5)) & 0xFF); (rotr3)
                // sbox lookup
                // XOR
                // This seems consistent.
                // However, to be SAFE for "Legacy", I will implement exactly the code block
                // from before.
                // It seems the "Logic" change was more impactful on Feistel. SPN might just be
                // the non-Base64 part.

                // 1. rotr3
                b = (((b >>> 3) | (b << 5)) & 0xFF);
                // 2. sbox inv
                int hi = (b >>> 4) & 0xF;
                int lo = b & 0xF;
                hi = inv[hi];
                lo = inv[lo];
                b = ((hi << 4) | lo);
                // 3. xor
                b ^= (k[r % k.length] & 0xFF);
                out[i] = (byte) b;
            }
        }
        return new String(out, StandardCharsets.UTF_8);
    }

    private static byte[] spnToy(byte[] data, String key, boolean enc) {
        byte[] k = (key == null || key.isEmpty() ? "k" : key).getBytes(StandardCharsets.UTF_8);

        int[] sbox = { 6, 4, 12, 5, 0, 7, 2, 14, 1, 15, 3, 13, 8, 10, 9, 11 };
        int[] inv = new int[16];
        for (int i = 0; i < 16; i++)
            inv[sbox[i]] = i;

        byte[] out = java.util.Arrays.copyOf(data, data.length);

        for (int round = 0; round < 8; round++) {
            int r = enc ? round : (7 - round);
            int kb = k[r % k.length] & 0xFF;

            for (int i = 0; i < out.length; i++) {
                int b = out[i] & 0xFF;

                if (enc) {
                    // XOR -> SBOX -> PERM
                    b ^= kb;

                    int hi = (b >>> 4) & 0xF, lo = b & 0xF;
                    hi = sbox[hi];
                    lo = sbox[lo];
                    b = ((hi << 4) | lo) & 0xFF;

                    // perm: rotl3
                    b = (((b << 3) | (b >>> 5)) & 0xFF);
                } else {
                    // invPERM -> invSBOX -> XOR
                    // inv perm: rotr3
                    b = (((b >>> 3) | (b << 5)) & 0xFF);

                    int hi = (b >>> 4) & 0xF, lo = b & 0xF;
                    hi = inv[hi];
                    lo = inv[lo];
                    b = ((hi << 4) | lo) & 0xFF;

                    b ^= kb;
                }

                out[i] = (byte) b;
            }
        }
        return out;
    }

    // =================================================================
    // RSA HELPERS
    // =================================================================

    public static KeyPair genRsaKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    public static String pubKeyToB64(PublicKey pub) {
        return Base64.getEncoder().encodeToString(pub.getEncoded());
    }

    public static PublicKey pubKeyFromB64(String b64) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(b64);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(bytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    public static String rsaWrapKeyUrlB64(PublicKey pub, byte[] keyBytes) throws Exception {
        // RSA/ECB/OAEPWithSHA-256AndMGF1Padding
        Cipher cipher;
        try {
            cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        } catch (Exception e) {
            // Fallback for older JDKs if SHA-256 OAEP not available default
            cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
        }
        cipher.init(Cipher.ENCRYPT_MODE, pub);
        byte[] wrapped = cipher.doFinal(keyBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(wrapped);
    }

    public static byte[] rsaUnwrapKeyUrlB64(PrivateKey prv, String urlB64) throws Exception {
        byte[] wrapped = Base64.getUrlDecoder().decode(urlB64);
        Cipher cipher;
        try {
            cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        } catch (Exception e) {
            cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
        }
        cipher.init(Cipher.DECRYPT_MODE, prv);
        return cipher.doFinal(wrapped);
    }

    // =================================================================
    // SYMMETRIC HELPERS (RAW KEY)
    // =================================================================

    public static String[] aesGcmEncryptWithKey(byte[] key16, String plain, String provider) throws Exception {
        // IV: 12 bytes standard for GCM
        byte[] iv = new byte[12];
        RNG.nextBytes(iv);

        Cipher cipher = (provider != null && !provider.isEmpty())
                ? Cipher.getInstance("AES/GCM/NoPadding", provider)
                : Cipher.getInstance("AES/GCM/NoPadding");

        GCMParameterSpec spec = new GCMParameterSpec(128, iv); // 128 bit tag
        SecretKeySpec keySpec = new SecretKeySpec(key16, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, spec);

        byte[] plainBytes = plain.getBytes(StandardCharsets.UTF_8);
        byte[] ct = cipher.doFinal(plainBytes);

        String ivB64 = Base64.getEncoder().encodeToString(iv);
        // Use URL-safe for payload containment
        String ctUrlB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(ct);

        return new String[] { ivB64, ctUrlB64 };
    }

    public static String aesGcmDecryptWithKey(byte[] key16, String ivB64, String ctUrlB64, String provider)
            throws Exception {
        byte[] iv = Base64.getDecoder().decode(ivB64);
        byte[] ct = Base64.getUrlDecoder().decode(ctUrlB64);

        Cipher cipher = (provider != null && !provider.isEmpty())
                ? Cipher.getInstance("AES/GCM/NoPadding", provider)
                : Cipher.getInstance("AES/GCM/NoPadding");

        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        SecretKeySpec keySpec = new SecretKeySpec(key16, "AES");
        cipher.init(Cipher.DECRYPT_MODE, keySpec, spec);

        byte[] plainBytes = cipher.doFinal(ct);
        return new String(plainBytes, StandardCharsets.UTF_8);
    }

    public static String desEcbEncryptWithKey(byte[] key8, String plain, String provider) throws Exception {
        Cipher cipher = (provider != null && !provider.isEmpty())
                ? Cipher.getInstance("DES/ECB/PKCS5Padding", provider)
                : Cipher.getInstance("DES/ECB/PKCS5Padding");

        SecretKeySpec keySpec = new SecretKeySpec(key8, "DES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);

        byte[] plainBytes = plain.getBytes(StandardCharsets.UTF_8);
        byte[] ct = cipher.doFinal(plainBytes);

        return Base64.getUrlEncoder().withoutPadding().encodeToString(ct);
    }

    public static String desEcbDecryptWithKey(byte[] key8, String ctUrlB64, String provider) throws Exception {
        byte[] ct = Base64.getUrlDecoder().decode(ctUrlB64);

        Cipher cipher = (provider != null && !provider.isEmpty())
                ? Cipher.getInstance("DES/ECB/PKCS5Padding", provider)
                : Cipher.getInstance("DES/ECB/PKCS5Padding");

        SecretKeySpec keySpec = new SecretKeySpec(key8, "DES");
        cipher.init(Cipher.DECRYPT_MODE, keySpec);

        byte[] plainBytes = cipher.doFinal(ct);
        return new String(plainBytes, StandardCharsets.UTF_8);
    }

    // =================================================================
    // HYBRID PAYLOAD CODECS (JSON v1 + Legacy fallback)
    // =================================================================

    /**
     * Produces: {"v":1,"ct":"...","keys":{"NickA":"...","NickB":"..."}}
     */
    public static String encodeHybridPayloadJsonV1(String ctUrlB64, Map<String, String> wrappedKeysByNick) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\"v\":1,\"ct\":\"").append(ctUrlB64).append("\",\"keys\":{");

        int i = 0;
        for (Map.Entry<String, String> entry : wrappedKeysByNick.entrySet()) {
            if (i > 0)
                sb.append(",");
            // Nicks might have chars needing escape. For simplicity assume simple nicks or
            // just escape double quotes?
            // User requirement says minimal escape.
            String nick = entry.getKey().replace("\"", "\\\"");
            String val = entry.getValue(); // URL-safe B64, no quotes

            sb.append("\"").append(nick).append("\":\"").append(val).append("\"");
            i++;
        }
        sb.append("}}");
        return sb.toString();
    }

    public static Object[] decodeHybridPayloadJsonV1(String json) {
        // Minimal parser
        // Expected structure: {"v":1,"ct":"<CT>","keys":{...}}
        // Returns Object[]{ String ctUrlB64, Map<String,String> keys }

        String ct = "";
        Map<String, String> keys = new java.util.HashMap<>();

        try {
            // Extract CT
            int idxCt = json.indexOf("\"ct\":\"");
            if (idxCt != -1) {
                int start = idxCt + 6;
                int end = json.indexOf("\"", start);
                if (end != -1) {
                    ct = json.substring(start, end);
                }
            }

            // Extract Keys object
            int idxKeys = json.indexOf("\"keys\":{");
            if (idxKeys != -1) {
                int start = idxKeys + 8;
                int end = json.indexOf("}", start);
                // "Simple" parser issue: if json continues after keys (e.g. }}), we just need
                // to find the matching brace
                // For this homework, we can just look for the first closing curly brace that
                // pairs with the opening one?
                // However, keys is the LAST element effectively.
                // Let's take substring from start to END of json, and find the last "}" or
                // similar.

                // Better approach for robust rudimentary parsing without full library:
                // Isolate the content inside keys:{ ... }
                // It ends before the final "}" of the main object.

                // Let's assume keys is the last field.
                // format: ... "keys":{"nick":"val",...}}

                if (end != -1) {
                    // Try to capture everything until the closing brace of 'keys' object.
                    // Since keys are B64 (no { or }), the first } after start is likely correct.
                    String content = json.substring(start, end);

                    if (!content.isEmpty()) {
                        String[] parts = content.split(",");
                        for (String p : parts) {
                            String[] kv = p.split(":");
                            if (kv.length >= 2) {
                                // removing quotes
                                String k = kv[0].trim().replaceAll("^\"|\"$", "").replace("\\\"", "\"");
                                String v = kv[1].trim().replaceAll("^\"|\"$", "");
                                keys.put(k, v);
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("JSON Parse Error: " + e.getMessage());
        }
        return new Object[] { ct, keys };
    }

    public static Object[] decodeHybridPayloadLegacyV1(String payloadPlain) {
        // Format: v1|ct=...|keys=nick1:wrap1,nick2:wrap2
        String ct = "";
        Map<String, String> keys = new java.util.HashMap<>();

        try {
            String[] parts = payloadPlain.split("\\|");
            for (String part : parts) {
                if (part.startsWith("ct=")) {
                    ct = part.substring(3);
                } else if (part.startsWith("keys=")) {
                    String kStr = part.substring(5);
                    if (!kStr.isEmpty()) {
                        String[] pairs = kStr.split(",");
                        for (String p : pairs) {
                            int cIdx = p.indexOf(":");
                            if (cIdx != -1) {
                                String n = p.substring(0, cIdx);
                                String w = p.substring(cIdx + 1);
                                keys.put(n, w);
                            }
                        }
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("Legacy Parse Error: " + e.getMessage());
        }
        return new Object[] { ct, keys };
    }

    // =================================================================
    // KEY DERIVATION HELPERS (HOMEWORK COMPLIANCE)
    // =================================================================

    /**
     * Ödev Şartı: AES-128 kullanılacak.
     * PBKDF2 ile 128-bit (16 byte) anahtar türetir.
     */
    public static byte[] deriveAes128KeyBytes(String password) {
        try {
            SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            // 256 yerine 128 bit istiyoruz
            KeySpec spec = new PBEKeySpec(password.toCharArray(), FIXED_SALT, 65536, 128);
            return f.generateSecret(spec).getEncoded();
        } catch (Exception e) {
            throw new RuntimeException("Key derivation failed: " + e.getMessage());
        }
    }

    /**
     * Ödev Şartı: DES için 64-bit (8 byte) anahtar.
     * Basit bir hash veya PBKDF2 ile 64 bit alabiliriz.
     */
    public static byte[] deriveDesKeyBytes(String password) {
        try {
            // DES key 8 bytes (56 bits effective)
            SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(password.toCharArray(), FIXED_SALT, 10000, 64);
            return f.generateSecret(spec).getEncoded();
        } catch (Exception e) {
            throw new RuntimeException("Key derivation failed: " + e.getMessage());
        }
    }
}
