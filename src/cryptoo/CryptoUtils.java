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

/**
 * Tüm şifreleme algoritmalarını toplayan yardımcı sınıf.
 *
 * - Klasik şifreler: CAESAR, VIGENERE, SUBSTITUTION, AFFINE,
 *   PLAYFAIR, RAILFENCE, ROUTE, COLUMNAR, POLYBIUS, PIGPEN
 * - Modern: AES_GCM (PBKDF2 / Session key), DES
 *
 * Not:
 *  - encrypt/decrypt fonksiyonları "kanonik metni" üretir/alır.
 *  - Client tarafında bu metin ayrıca Base64 ile sarılır (wire-level için).
 */
public final class CryptoUtils {

    // ---- Algoritma kodları (wire-level'da da bunlar kullanılıyor) ----
    public static final String ALGO_NONE       = "NONE";
    public static final String ALGO_CAESAR     = "CAESAR";
    public static final String ALGO_VIGENERE   = "VIGENERE";
    public static final String ALGO_SUBST      = "SUBSTITUTION";
    public static final String ALGO_AFFINE     = "AFFINE";
    public static final String ALGO_PLAYFAIR   = "PLAYFAIR";
    public static final String ALGO_RAILFENCE  = "RAILFENCE";
    public static final String ALGO_ROUTE      = "ROUTE";
    public static final String ALGO_COLUMNAR   = "COLUMNAR";
    public static final String ALGO_POLYBIUS   = "POLYBIUS";
    public static final String ALGO_PIGPEN     = "PIGPEN";
    public static final String ALGO_AES_GCM    = "AES_GCM";
    public static final String ALGO_DES        = "DES";
    public static final String ALGO_HILL       = "HILL";
    public static final String ALGO_3DES       = "3DES";
    public static final String ALGO_BLOWFISH   = "BLOWFISH";
    public static final String ALGO_GOST       = "GOST";
    public static final String ALGO_FEISTEL    = "FEISTEL"; // toy
    public static final String ALGO_SPN        = "SPN";     // toy


    // ---- Ortak sabitler ----
    private static final String TR_ALPHABET = "ABCÇDEFGĞHIİJKLMNOÖPRSŞTUÜVYZ";
    private static final SecureRandom RNG = new SecureRandom();
    private static final byte[] FIXED_SALT = "SecureChatFixedSalt".getBytes(StandardCharsets.UTF_8);

    static {
        // BouncyCastle provider'ı ekle (DES/AES için şart değil ama ileride lazım olabilir)
        BCConfig.init();
    }

    private CryptoUtils() {}

    // =================================================================
    // GENEL ENCRYPT / DECRYPT
    // =================================================================

    public static String encrypt(String algoCode, String plain, String key) throws Exception {
        if (algoCode == null || ALGO_NONE.equals(algoCode)) {
            return plain;
        }
        if (plain == null) plain = "";

        switch (algoCode) {
            case ALGO_CAESAR: {
                int shift = parseIntSafe(key, 0);
                return caesarEncrypt(plain, shift);
            }
            case ALGO_VIGENERE:
                return vigenereEncrypt(plain, key);
            case ALGO_SUBST:
                return substitutionEncryptAuto(plain, key);
            case ALGO_AFFINE:
                return affineEncryptAuto(plain, key);
            case ALGO_PLAYFAIR:
                return playfairEncrypt(plain, key);
            case ALGO_RAILFENCE:
                return railFenceEncryptAuto(plain, key);
            case ALGO_ROUTE:
                return routeEncryptAuto(plain, key);
            case ALGO_COLUMNAR:
                return columnarEncrypt(plain, key);
            case ALGO_POLYBIUS:
                return polybiusEncrypt(plain);
            case ALGO_PIGPEN:
                return pigpenEncrypt(plain);
            case ALGO_AES_GCM:
                return aesGcmEncryptCanonical(plain, key);
            case ALGO_DES:
                return desEncryptCanonical(plain, key);
            case ALGO_HILL:
                return hillEncryptAuto(plain, key);
            case ALGO_3DES:
                return tripleDesEncryptCanonical(plain, key);
            case ALGO_BLOWFISH:
                return blowfishEncryptCanonical(plain, key);
            case ALGO_GOST:
                return gostEncryptCanonical(plain, key);
            case ALGO_FEISTEL:
                return feistelToyEncrypt(plain, key);
            case ALGO_SPN:
                return spnToyEncrypt(plain, key);
            default:
                return plain;
        }
    }

    public static String decrypt(String algoCode, String cipher, String key) throws Exception {
        if (algoCode == null || ALGO_NONE.equals(algoCode)) {
            return cipher;
        }
        if (cipher == null) cipher = "";

        switch (algoCode) {
            case ALGO_CAESAR: {
                int shift = parseIntSafe(key, 0);
                return caesarDecrypt(cipher, shift);
            }
            case ALGO_VIGENERE:
                return vigenereDecrypt(cipher, key);
            case ALGO_SUBST:
                return substitutionDecryptAuto(cipher, key);
            case ALGO_AFFINE:
                return affineDecryptAuto(cipher, key);
            case ALGO_PLAYFAIR:
                return playfairDecrypt(cipher, key);
            case ALGO_RAILFENCE:
                return railFenceDecryptAuto(cipher, key);
            case ALGO_ROUTE:
                return routeDecryptAuto(cipher, key);
            case ALGO_COLUMNAR:
                return columnarDecrypt(cipher, key);
            case ALGO_POLYBIUS:
                return polybiusDecrypt(cipher);
            case ALGO_PIGPEN:
                return pigpenDecrypt(cipher);
            case ALGO_AES_GCM:
                return aesGcmDecryptCanonical(cipher, key);
            case ALGO_DES:
                return desDecryptCanonical(cipher, key);
            case ALGO_HILL:
                return hillDecryptAuto(cipher, key);
            case ALGO_3DES:
                return tripleDesDecryptCanonical(cipher, key);
            case ALGO_BLOWFISH:
                return blowfishDecryptCanonical(cipher, key);
            case ALGO_GOST:
                return gostDecryptCanonical(cipher, key);
            case ALGO_FEISTEL:
                return feistelToyDecrypt(cipher, key);
            case ALGO_SPN:
                return spnToyDecrypt(cipher, key);
            default:
                return cipher;
        }
    }

    private static int parseIntSafe(String s, int def) {
        try {
            if (s == null) return def;
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
        if (isTrLetter(ch)) return Character.toUpperCase(ch);
        return ch;
    }

    private static String normalizeText(String s, boolean lettersOnly) {
        if (s == null) return "";
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

    private static int alphaIndex(char u) {
        return TR_ALPHABET.indexOf(u);
    }

    // =================================================================
    // CAESAR
    // =================================================================

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

    private static String caesarDecrypt(String cipher, int shift) {
        return caesarEncrypt(cipher, -shift);
    }

    // =================================================================
    // VIGENERE
    // =================================================================

    private static String vigenereEncrypt(String text, String keyRaw) {
        String textN = normalizeText(text, false);
        String keyN  = normalizeText(keyRaw == null ? "" : keyRaw, true);
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
        String keyN = normalizeText(keyRaw == null ? "" : keyRaw, true);
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

    // =================================================================
    // SUBSTITUTION
    // =================================================================

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
        for (int i = 0; i < n; i++) map[i] = i;
        if (key == null) return map;
        String kOnly = normalizeText(key, true);
        if (kOnly.length() == n) {
            for (int i = 0; i < n; i++) {
                int j = TR_ALPHABET.indexOf(kOnly.charAt(i));
                if (j >= 0) map[i] = j;
            }
            return map;
        }
        String[] pairs = key.split("[;\n]+");
        for (String p : pairs) {
            String[] ab = p.split(":");
            if (ab.length == 2) {
                String a = normalizeText(ab[0], true);
                String b = normalizeText(ab[1], true);
                if (a.length() == 1 && b.length() == 1) {
                    int ia = TR_ALPHABET.indexOf(a.charAt(0));
                    int ib = TR_ALPHABET.indexOf(b.charAt(0));
                    if (ia >= 0 && ib >= 0) map[ia] = ib;
                }
            }
        }
        return map;
    }

    private static String substitutionApply(String s, int[] map, boolean enc) {
        StringBuilder out = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            char u = safeChar(c);
            int idx = TR_ALPHABET.indexOf(u);
            if (idx >= 0) {
                int t = enc ? map[idx] : inverseMap(map, idx);
                out.append(TR_ALPHABET.charAt(t));
            } else out.append(c);
        }
        return out.toString();
    }

    private static int inverseMap(int[] map, int y) {
        for (int i = 0; i < map.length; i++)
            if (map[i] == y) return i;
        return y;
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
            try { if (t.length > 0) a = Integer.parseInt(t[0].trim()); } catch (Exception ignored) {}
            try { if (t.length > 1) b = Integer.parseInt(t[1].trim()); } catch (Exception ignored) {}
        }
        return new int[]{a, b};
    }

    private static int egcdInv(int a, int m) {
        int t = 0, newt = 1, r = m, newr = a % m;
        if (newr < 0) newr += m;
        while (newr != 0) {
            int q = r / newr;
            int tmp = t - q * newt; t = newt; newt = tmp;
            tmp = r - q * newr; r = newr; newr = tmp;
        }
        if (r > 1) return 1;
        if (t < 0) t += m;
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
                if (ni < 0) ni += n;
                out.append(TR_ALPHABET.charAt(ni));
            } else out.append(c);
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
                if (ni < 0) ni += n;
                out.append(TR_ALPHABET.charAt(ni));
            } else out.append(c);
        }
        return out.toString();
    }

    // =================================================================
    // RAIL FENCE
    // =================================================================

    private static String railFenceEncryptAuto(String text, String key) {
        int rails = 2;
        try { rails = Integer.parseInt(key.trim()); } catch (Exception ignored) {}
        return railFenceEncrypt(text, rails);
    }

    private static String railFenceDecryptAuto(String cipher, String key) {
        int rails = 2;
        try { rails = Integer.parseInt(key.trim()); } catch (Exception ignored) {}
        return railFenceDecrypt(cipher, rails);
    }

    private static String railFenceEncrypt(String text, int rails) {
        if (rails <= 1) return text;
        StringBuilder[] rows = new StringBuilder[rails];
        for (int i = 0; i < rails; i++) rows[i] = new StringBuilder();
        int r = 0, dir = 1;
        for (int i = 0; i < text.length(); i++) {
            rows[r].append(text.charAt(i));
            r += dir;
            if (r == rails - 1) dir = -1;
            else if (r == 0) dir = 1;
        }
        StringBuilder out = new StringBuilder(text.length());
        for (int i = 0; i < rails; i++) out.append(rows[i]);
        return out.toString();
    }

    private static String railFenceDecrypt(String cipher, int rails) {
        if (rails <= 1) return cipher;
        int len = cipher.length();
        boolean[][] mark = new boolean[rails][len];
        int r = 0, dir = 1;
        for (int j = 0; j < len; j++) {
            mark[r][j] = true;
            r += dir;
            if (r == rails - 1) dir = -1;
            else if (r == 0) dir = 1;
        }
        char[][] grid = new char[rails][len];
        int idx = 0;
        for (int i = 0; i < rails; i++) {
            for (int j = 0; j < len; j++) {
                if (mark[i][j]) grid[i][j] = cipher.charAt(idx++);
            }
        }
        StringBuilder res = new StringBuilder(len);
        r = 0; dir = 1;
        for (int j = 0; j < len; j++) {
            res.append(grid[r][j]);
            r += dir;
            if (r == rails - 1) dir = -1;
            else if (r == 0) dir = 1;
        }
        return res.toString();
    }

    // =================================================================
    // ROUTE (SPIRAL)
    // =================================================================

    private static String routeEncryptAuto(String text, String key) {
        int cols = 3; boolean cw = true;
        if (key != null && !key.isEmpty()) {
            String k = key.toLowerCase();
            try { cols = Integer.parseInt(k.replaceAll("[^0-9]", "")); } catch (Exception ignored) {}
            if (k.contains("ccw") || k.contains("counter")) cw = false;
        }
        return routeEncrypt(text, cols, cw);
    }

    private static String routeDecryptAuto(String cipher, String key) {
        int cols = 3; boolean cw = true;
        if (key != null && !key.isEmpty()) {
            String k = key.toLowerCase();
            try { cols = Integer.parseInt(k.replaceAll("[^0-9]", "")); } catch (Exception ignored) {}
            if (k.contains("ccw") || k.contains("counter")) cw = false;
        }
        return routeDecrypt(cipher, cols, cw);
    }

    private static String routeEncrypt(String text, int cols, boolean clockwise) {
        if (cols <= 1) return text;
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
                    if (pos < len) { out.append(grid[top][j]); taken++; }
                }
                top++;
                for (int i = top; i <= bottom && taken < len; i++) {
                    int pos = i * cols + right;
                    if (pos < len) { out.append(grid[i][right]); taken++; }
                }
                right--;
                if (top <= bottom) {
                    for (int j = right; j >= left && taken < len; j--) {
                        int pos = bottom * cols + j;
                        if (pos < len) { out.append(grid[bottom][j]); taken++; }
                    }
                    bottom--;
                }
                if (left <= right) {
                    for (int i = bottom; i >= top && taken < len; i--) {
                        int pos = i * cols + left;
                        if (pos < len) { out.append(grid[i][left]); taken++; }
                    }
                    left++;
                }
            } else {
                for (int i = top; i <= bottom && taken < len; i++) {
                    int pos = i * cols + left;
                    if (pos < len) { out.append(grid[i][left]); taken++; }
                }
                left++;
                for (int j = left; j <= right && taken < len; j++) {
                    int pos = bottom * cols + j;
                    if (pos < len) { out.append(grid[bottom][j]); taken++; }
                }
                bottom--;
                if (left <= right) {
                    for (int i = bottom; i >= top && taken < len; i--) {
                        int pos = i * cols + right;
                        if (pos < len) { out.append(grid[i][right]); taken++; }
                    }
                    right--;
                }
                if (top <= bottom) {
                    for (int j = right; j >= left && taken < len; j--) {
                        int pos = top * cols + j;
                        if (pos < len) { out.append(grid[top][j]); taken++; }
                    }
                    top++;
                }
            }
        }
        return out.toString();
    }

    private static String routeDecrypt(String cipher, int cols, boolean clockwise) {
        if (cols <= 1) return cipher;
        int len = cipher.length();
        int rows = (len + cols - 1) / cols;
        char[][] grid = new char[rows][cols];
        int top = 0, bottom = rows - 1, left = 0, right = cols - 1, idx = 0;

        while (top <= bottom && left <= right && idx < len) {
            if (clockwise) {
                for (int j = left; j <= right && idx < len; j++) {
                    int pos = top * cols + j;
                    if (pos < len) grid[top][j] = cipher.charAt(idx++);
                }
                top++;
                for (int i = top; i <= bottom && idx < len; i++) {
                    int pos = i * cols + right;
                    if (pos < len) grid[i][right] = cipher.charAt(idx++);
                }
                right--;
                if (top <= bottom) {
                    for (int j = right; j >= left && idx < len; j--) {
                        int pos = bottom * cols + j;
                        if (pos < len) grid[bottom][j] = cipher.charAt(idx++);
                    }
                    bottom--;
                }
                if (left <= right) {
                    for (int i = bottom; i >= top && idx < len; i--) {
                        int pos = i * cols + left;
                        if (pos < len) grid[i][left] = cipher.charAt(idx++);
                    }
                    left++;
                }
            } else {
                for (int i = top; i <= bottom && idx < len; i++) {
                    int pos = i * cols + left;
                    if (pos < len) grid[i][left] = cipher.charAt(idx++);
                }
                left++;
                for (int j = left; j <= right && idx < len; j++) {
                    int pos = bottom * cols + j;
                    if (pos < len) grid[bottom][j] = cipher.charAt(idx++);
                }
                bottom--;
                if (left <= right) {
                    for (int i = bottom; i >= top && idx < len; i--) {
                        int pos = i * cols + right;
                        if (pos < len) grid[i][right] = cipher.charAt(idx++);
                    }
                    right--;
                }
                if (top <= bottom) {
                    for (int j = right; j >= left && idx < len; j--) {
                        int pos = top * cols + j;
                        if (pos < len) grid[top][j] = cipher.charAt(idx++);
                    }
                    top++;
                }
            }
        }

        StringBuilder out = new StringBuilder(len);
        int count = 0;
        for (int i = 0; i < rows; i++)
            for (int j = 0; j < cols; j++) {
                if (count < len) out.append(grid[i][j]);
                count++;
            }
        return out.toString();
    }

    // =================================================================
    // COLUMNAR TRANSPOSITION
    // =================================================================

    private static String columnarEncrypt(String text, String key) {
        if (key == null || key.isEmpty()) return text;
        String k = normalizeText(key, true);
        if (k.isEmpty()) return text;
        int cols = k.length(), len = text.length(), rows = (len + cols - 1) / cols;
        int[] order = columnOrder(k);
        StringBuilder out = new StringBuilder(len);
        for (int oi = 0; oi < cols; oi++) {
            int col = order[oi];
            for (int r = 0; r < rows; r++) {
                int idx = r * cols + col;
                if (idx < len) out.append(text.charAt(idx));
            }
        }
        return out.toString();
    }

    private static String columnarDecrypt(String cipher, String key) {
        if (key == null || key.isEmpty()) return cipher;
        String k = normalizeText(key, true);
        if (k.isEmpty()) return cipher;
        int cols = k.length(), len = cipher.length(), rows = (len + cols - 1) / cols, rem = len % cols;
        int[] order = columnOrder(k);
        int[] colHeights = new int[cols];
        for (int c = 0; c < cols; c++) colHeights[c] = rows - ((rem != 0 && c >= rem) ? 1 : 0);
        char[][] grid = new char[rows][cols];
        int idx = 0;
        for (int oi = 0; oi < cols; oi++) {
            int col = order[oi], h = colHeights[col];
            for (int r = 0; r < h; r++) grid[r][col] = cipher.charAt(idx++);
        }
        StringBuilder out = new StringBuilder(len);
        for (int r = 0; r < rows; r++)
            for (int c = 0; c < cols; c++) {
                int pos = r * cols + c;
                if (pos < len) out.append(grid[r][c]);
            }
        return out.toString();
    }

    private static int[] columnOrder(String k) {
        int n = k.length();
        Integer[] idx = new Integer[n];
        for (int i = 0; i < n; i++) idx[i] = i;
        java.util.Arrays.sort(idx, (a, b) -> {
            char ca = k.charAt(a), cb = k.charAt(b);
            if (ca == cb) return Integer.compare(a, b);
            return Character.compare(ca, cb);
        });
        int[] order = new int[n];
        for (int i = 0; i < n; i++) order[i] = idx[i];
        return order;
    }

    // =================================================================
    // POLYBIUS (5x5)
    // =================================================================

    private static String polybiusEncrypt(String text) {
        String alpha = "ABCDEFGHIKLMNOPQRSTUVWXYZ"; // J yok, I/J birleşik
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < text.length(); i++) {
            char u = polyLatin(text.charAt(i));
            int p = alpha.indexOf(u);
            if (p >= 0) {
                int r = p / 5 + 1, c = p % 5 + 1;
                out.append(r).append(c).append(' ');
            } else out.append(text.charAt(i));
        }
        return out.toString().trim();
    }

    private static String polybiusDecrypt(String cipher) {
        String alpha = "ABCDEFGHIKLMNOPQRSTUVWXYZ";
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < cipher.length(); ) {
            char a = cipher.charAt(i);
            if (a >= '1' && a <= '5' && i + 1 < cipher.length()) {
                char b = cipher.charAt(i + 1);
                if (b >= '1' && b <= '5') {
                    int idx = (a - '0' - 1) * 5 + (b - '0' - 1);
                    if (idx >= 0 && idx < 25) {
                        out.append(alpha.charAt(idx));
                        i += 2;
                        if (i < cipher.length() && cipher.charAt(i) == ' ') i++;
                        continue;
                    }
                }
            }
            out.append(a);
            i++;
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
            case 'J': return 'I';  // I/J birleşik
            default: return (u >= 'A' && u <= 'Z') ? u : ch;
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
                if (c == 'J') c = 'I';
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
            if (u == 'J') u = 'I';
            if (u < 'A' || u > 'Z') u = 'X';
            return new int[]{pos[u - 'A'][0], pos[u - 'A'][1]};
        }

        String prepareText(String s, boolean forEnc) {
            StringBuilder t = new StringBuilder();
            for (int i = 0; i < s.length(); i++) {
                char u = polyLatin(s.charAt(i));
                if (u >= 'A' && u <= 'Z') {
                    if (u == 'J') u = 'I';
                    t.append(u);
                }
            }
            StringBuilder d = new StringBuilder();
            for (int i = 0; i < t.length(); ) {
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
            if (d.length() % 2 == 1) d.append('X');
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
                if (out.length() > 0) out.append('|');
                out.append("/static/pigpen/").append(u).append(".png");
            } else {
                if (out.length() > 0) out.append('|');
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
            } else out.append(t);
        }
        return out.toString();
    }

    // =================================================================
    // AES-GCM (Parola veya Session key)
    // =================================================================

    /**
     * Kanonik format: ivBase64:cipherBase64
     */
    private static String aesGcmEncryptCanonical(String plain, String keyStr) throws Exception {
        if (keyStr == null || keyStr.isEmpty()) {
            throw new IllegalArgumentException("AES-GCM için parola veya session key gerekir.");
        }
        byte[] keyBytes = deriveAesKeyBytes(keyStr);
        SecretKey key = new SecretKeySpec(keyBytes, "AES");

        byte[] iv = new byte[12];
        RNG.nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        byte[] ct = cipher.doFinal(plain.getBytes(StandardCharsets.UTF_8));

        String ivB64 = Base64.getEncoder().encodeToString(iv);
        String ctB64 = Base64.getEncoder().encodeToString(ct);
        return ivB64 + ":" + ctB64;
    }

    private static String aesGcmDecryptCanonical(String canonical, String keyStr) throws Exception {
        if (keyStr == null || keyStr.isEmpty()) {
            throw new IllegalArgumentException("AES-GCM çözmek için parola veya session key gerekir.");
        }
        String[] parts = canonical.split(":", 2);
        if (parts.length != 2) throw new IllegalArgumentException("AES-GCM kanonik format bozuk.");
        byte[] iv = Base64.getDecoder().decode(parts[0]);
        byte[] ct = Base64.getDecoder().decode(parts[1]);

        byte[] keyBytes = deriveAesKeyBytes(keyStr);
        SecretKey key = new SecretKeySpec(keyBytes, "AES");

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);
        byte[] pt = cipher.doFinal(ct);
        return new String(pt, StandardCharsets.UTF_8);
    }

    /**
     * keyStr:
     *   - Eğer uzun ve Base64 görünümündeyse → direkt raw key (session key)
     *   - Diğer durumda → PBKDF2 ile parola'dan key türet
     */
    private static byte[] deriveAesKeyBytes(String keyStr) throws Exception {
        String trimmed = keyStr.trim();
        if (looksLikeBase64Key(trimmed)) {
            // Session key (Base64)
            byte[] raw = Base64.getDecoder().decode(trimmed);
            if (raw.length == 16 || raw.length == 24 || raw.length == 32) {
                return raw;
            }
            // Uzunluk uymuyorsa PBKDF2'ye düşelim
        }
        // Parola tabanlı
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(trimmed.toCharArray(), FIXED_SALT, 65536, 256);
        SecretKey sk = f.generateSecret(spec);
        return sk.getEncoded();
    }

    private static boolean looksLikeBase64Key(String s) {
        if (s == null) return false;
        s = s.trim();
        if (s.length() < 40) return false;
        return s.matches("^[A-Za-z0-9+/=]+$");
    }

    // =================================================================
    // DES (ECB / PKCS5Padding) — Eğitim amaçlı
    // =================================================================

    /**
     * Kanonik format: cipherBase64
     */
    private static String desEncryptCanonical(String plain, String keyStr) throws Exception {
        if (keyStr == null || keyStr.isEmpty()) {
            throw new IllegalArgumentException("DES için en az 8 karakterlik anahtar gir.");
        }
        byte[] keyBytes = keyStr.getBytes(StandardCharsets.UTF_8);
        byte[] k8 = new byte[8];
        for (int i = 0; i < 8; i++) {
            k8[i] = (i < keyBytes.length) ? keyBytes[i] : 0;
        }
        SecretKeySpec sk = new SecretKeySpec(k8, "DES");
        Cipher c = Cipher.getInstance("DES/ECB/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, sk);
        byte[] ct = c.doFinal(plain.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(ct);
    }

    private static String desDecryptCanonical(String canonical, String keyStr) throws Exception {
        if (keyStr == null || keyStr.isEmpty()) {
            throw new IllegalArgumentException("DES için en az 8 karakterlik anahtar gir.");
        }
        byte[] keyBytes = keyStr.getBytes(StandardCharsets.UTF_8);
        byte[] k8 = new byte[8];
        for (int i = 0; i < 8; i++) {
            k8[i] = (i < keyBytes.length) ? keyBytes[i] : 0;
        }
        SecretKeySpec sk = new SecretKeySpec(k8, "DES");
        Cipher c = Cipher.getInstance("DES/ECB/PKCS5Padding");
        c.init(Cipher.DECRYPT_MODE, sk);
        byte[] ct = Base64.getDecoder().decode(canonical);
        byte[] pt = c.doFinal(ct);
        return new String(pt, StandardCharsets.UTF_8);
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
            if (isTrLetter(ch)) buf.append(ch);
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
        if (letters.isEmpty()) return "";
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

        HillKey(int n, int[][] m) { this.n = n; this.m = m; }

        static HillKey parse(String key) {
            if (key == null) throw new IllegalArgumentException("Hill key boş olamaz");
            String[] parts = key.split("[,;\\s]+");
            if (parts.length == 4) {
                int[][] m = new int[][]{
                        { Integer.parseInt(parts[0]), Integer.parseInt(parts[1]) },
                        { Integer.parseInt(parts[2]), Integer.parseInt(parts[3]) }
                };
                return new HillKey(2, m);
            } else if (parts.length == 9) {
                int[][] m = new int[][]{
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
                for (int j = 0; j < n; j++) sum += (long)m[i][j] * v[j];
                int x = (int)(sum % mod);
                if (x < 0) x += mod;
                r[i] = x;
            }
            return r;
        }

        HillKey inverse() {
            // 2x2 ve 3x3 için modüler ters (basit eğitim implementasyonu)
            int mod = TR_ALPHABET.length();
            if (n == 2) return inverse2(mod);
            if (n == 3) return inverse3(mod);
            throw new IllegalStateException("Hill inverse sadece 2x2/3x3 destekli.");
        }

        private HillKey inverse2(int mod) {
            int a=m[0][0], b=m[0][1], c=m[1][0], d=m[1][1];
            int det = (a*d - b*c) % mod; if (det<0) det+=mod;
            int detInv = modInverse(det, mod);
            int[][] inv = new int[][]{
                    { ( d*detInv)%mod, ((-b)*detInv)%mod },
                    { ((-c)*detInv)%mod, ( a*detInv)%mod }
            };
            for (int i=0;i<2;i++) for(int j=0;j<2;j++){ inv[i][j]%=mod; if(inv[i][j]<0) inv[i][j]+=mod; }
            return new HillKey(2, inv);
        }

        private HillKey inverse3(int mod) {
            int[][] A = m;
            int det =
                    A[0][0]*(A[1][1]*A[2][2]-A[1][2]*A[2][1]) -
                    A[0][1]*(A[1][0]*A[2][2]-A[1][2]*A[2][0]) +
                    A[0][2]*(A[1][0]*A[2][1]-A[1][1]*A[2][0]);
            det %= mod; if (det<0) det+=mod;
            int detInv = modInverse(det, mod);

            int[][] adj = new int[3][3];
            adj[0][0] =  (A[1][1]*A[2][2]-A[1][2]*A[2][1]);
            adj[0][1] = -(A[1][0]*A[2][2]-A[1][2]*A[2][0]);
            adj[0][2] =  (A[1][0]*A[2][1]-A[1][1]*A[2][0]);

            adj[1][0] = -(A[0][1]*A[2][2]-A[0][2]*A[2][1]);
            adj[1][1] =  (A[0][0]*A[2][2]-A[0][2]*A[2][0]);
            adj[1][2] = -(A[0][0]*A[2][1]-A[0][1]*A[2][0]);

            adj[2][0] =  (A[0][1]*A[1][2]-A[0][2]*A[1][1]);
            adj[2][1] = -(A[0][0]*A[1][2]-A[0][2]*A[1][0]);
            adj[2][2] =  (A[0][0]*A[1][1]-A[0][1]*A[1][0]);

            // transpose(adj) * detInv
            int[][] inv = new int[3][3];
            for (int i=0;i<3;i++) for(int j=0;j<3;j++){
                long x = (long)adj[j][i] * detInv;
                int v = (int)(x % mod); if(v<0) v+=mod;
                inv[i][j] = v;
            }
            return new HillKey(3, inv);
        }
    }

    private static int modInverse(int a, int m) {
        // a^-1 mod m
        int t=0, newt=1, r=m, newr=a%m;
        if (newr<0) newr+=m;
        while(newr!=0){
            int q=r/newr;
            int tmp=t-q*newt; t=newt; newt=tmp;
            tmp=r-q*newr; r=newr; newr=tmp;
        }
        if (r!=1) throw new IllegalArgumentException("Hill key determinant invertible değil (mod " + m + ")");
        if (t<0) t+=m;
        return t;
    }

	 // ======================= 3DES =======================
	 // Kanonik format: cipherBase64
	 private static String tripleDesEncryptCanonical(String plain, String keyStr) throws Exception {
	     if (keyStr == null || keyStr.isEmpty()) throw new IllegalArgumentException("3DES key gerekli");
	     byte[] k = keyStr.getBytes(StandardCharsets.UTF_8);
	     byte[] k24 = new byte[24];
	     for (int i = 0; i < 24; i++) k24[i] = (i < k.length) ? k[i] : 0;
	
	     javax.crypto.SecretKey key = new javax.crypto.spec.SecretKeySpec(k24, "DESede");
	     javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("DESede/ECB/PKCS5Padding");
	     c.init(javax.crypto.Cipher.ENCRYPT_MODE, key);
	     byte[] ct = c.doFinal(plain.getBytes(StandardCharsets.UTF_8));
	     return Base64.getEncoder().encodeToString(ct);
	 }
	
	 private static String tripleDesDecryptCanonical(String canonical, String keyStr) throws Exception {
	     if (keyStr == null || keyStr.isEmpty()) throw new IllegalArgumentException("3DES key gerekli");
	     byte[] k = keyStr.getBytes(StandardCharsets.UTF_8);
	     byte[] k24 = new byte[24];
	     for (int i = 0; i < 24; i++) k24[i] = (i < k.length) ? k[i] : 0;
	
	     javax.crypto.SecretKey key = new javax.crypto.spec.SecretKeySpec(k24, "DESede");
	     javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("DESede/ECB/PKCS5Padding");
	     c.init(javax.crypto.Cipher.DECRYPT_MODE, key);
	     byte[] pt = c.doFinal(Base64.getDecoder().decode(canonical));
	     return new String(pt, StandardCharsets.UTF_8);
	 }
	 
	// ======================= BLOWFISH =======================
	// Kanonik format: cipherBase64
	private static String blowfishEncryptCanonical(String plain, String keyStr) throws Exception {
	    if (keyStr == null || keyStr.isEmpty()) throw new IllegalArgumentException("Blowfish key gerekli");
	    byte[] k = keyStr.getBytes(StandardCharsets.UTF_8);
	    javax.crypto.SecretKey key = new javax.crypto.spec.SecretKeySpec(k, "Blowfish");
	    javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("Blowfish/ECB/PKCS5Padding");
	    c.init(javax.crypto.Cipher.ENCRYPT_MODE, key);
	    byte[] ct = c.doFinal(plain.getBytes(StandardCharsets.UTF_8));
	    return Base64.getEncoder().encodeToString(ct);
	}

	private static String blowfishDecryptCanonical(String canonical, String keyStr) throws Exception {
	    if (keyStr == null || keyStr.isEmpty()) throw new IllegalArgumentException("Blowfish key gerekli");
	    byte[] k = keyStr.getBytes(StandardCharsets.UTF_8);
	    javax.crypto.SecretKey key = new javax.crypto.spec.SecretKeySpec(k, "Blowfish");
	    javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("Blowfish/ECB/PKCS5Padding");
	    c.init(javax.crypto.Cipher.DECRYPT_MODE, key);
	    byte[] pt = c.doFinal(Base64.getDecoder().decode(canonical));
	    return new String(pt, StandardCharsets.UTF_8);
	}

	// ======================= GOST 28147 =======================
	// Kanonik format: cipherBase64
	private static String gostEncryptCanonical(String plain, String keyStr) throws Exception {
	    if (keyStr == null || keyStr.isEmpty()) throw new IllegalArgumentException("GOST key gerekli");
	    byte[] k = keyStr.getBytes(StandardCharsets.UTF_8);
	    // GOST key 32 byte ister; kısaysa pad
	    byte[] k32 = new byte[32];
	    for (int i = 0; i < 32; i++) k32[i] = (i < k.length) ? k[i] : 0;

	    javax.crypto.SecretKey key = new javax.crypto.spec.SecretKeySpec(k32, "GOST28147");
	    javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("GOST28147/ECB/PKCS5Padding", "BC");
	    c.init(javax.crypto.Cipher.ENCRYPT_MODE, key);
	    byte[] ct = c.doFinal(plain.getBytes(StandardCharsets.UTF_8));
	    return Base64.getEncoder().encodeToString(ct);
	}

	private static String gostDecryptCanonical(String canonical, String keyStr) throws Exception {
	    if (keyStr == null || keyStr.isEmpty()) throw new IllegalArgumentException("GOST key gerekli");
	    byte[] k = keyStr.getBytes(StandardCharsets.UTF_8);
	    byte[] k32 = new byte[32];
	    for (int i = 0; i < 32; i++) k32[i] = (i < k.length) ? k[i] : 0;

	    javax.crypto.SecretKey key = new javax.crypto.spec.SecretKeySpec(k32, "GOST28147");
	    javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("GOST28147/ECB/PKCS5Padding", "BC");
	    c.init(javax.crypto.Cipher.DECRYPT_MODE, key);
	    byte[] pt = c.doFinal(Base64.getDecoder().decode(canonical));
	    return new String(pt, StandardCharsets.UTF_8);
	}

	// ======================= FEISTEL (TOY) =======================
	// Kanonik format: base64(bytes)
	private static String feistelToyEncrypt(String plain, String key) {
	    byte[] data = plain.getBytes(StandardCharsets.UTF_8);
	    byte[] out = feistelToy(data, key, true);
	    return Base64.getEncoder().encodeToString(out);
	}

	private static String feistelToyDecrypt(String canonical, String key) {
	    byte[] ct = Base64.getDecoder().decode(canonical);
	    byte[] out = feistelToy(ct, key, false);
	    return new String(out, StandardCharsets.UTF_8);
	}

	private static byte[] feistelToy(byte[] input, String key, boolean enc) {
	    byte[] k = (key == null ? "k" : key).getBytes(StandardCharsets.UTF_8);
	    byte[] buf = java.util.Arrays.copyOf(input, input.length + (input.length % 2));
	    for (int round = 0; round < 16; round++) {
	        int r = enc ? round : (15 - round);
	        for (int i = 0; i + 1 < buf.length; i += 2) {
	            byte L = buf[i];
	            byte R = buf[i + 1];
	            byte f = (byte)( (R ^ k[r % k.length]) + r );
	            buf[i] = R;
	            buf[i + 1] = (byte)(L ^ f);
	        }
	    }
	    return buf;
	}

	// ======================= SPN (TOY) =======================
	private static String spnToyEncrypt(String plain, String key) {
	    byte[] in = plain.getBytes(StandardCharsets.UTF_8);
	    return Base64.getEncoder().encodeToString(spnToy(in, key, true));
	}
	private static String spnToyDecrypt(String canonical, String key) {
	    byte[] ct = Base64.getDecoder().decode(canonical);
	    return new String(spnToy(ct, key, false), StandardCharsets.UTF_8);
	}
	private static byte[] spnToy(byte[] data, String key, boolean enc) {
	    byte[] k = (key == null ? "k" : key).getBytes(StandardCharsets.UTF_8);
	    int[] sbox = {6,4,12,5,0,7,2,14,1,15,3,13,8,10,9,11};
	    int[] inv  = new int[16];
	    for(int i=0;i<16;i++) inv[sbox[i]]=i;

	    byte[] out = java.util.Arrays.copyOf(data, data.length);
	    for (int round=0; round<8; round++) {
	        int r = enc ? round : (7-round);
	        for (int i=0;i<out.length;i++) {
	            int b = out[i] & 0xFF;
	            b ^= (k[r % k.length] & 0xFF);
	            int hi = (b>>>4)&0xF, lo=b&0xF;
	            hi = enc ? sbox[hi] : inv[hi];
	            lo = enc ? sbox[lo] : inv[lo];
	            int sb = (hi<<4)|lo;
	            // toy perm: bit rotate
	            int p = enc ? ((sb<<3)|(sb>>>5)) & 0xFF : ((sb>>>3)|(sb<<5)) & 0xFF;
	            out[i] = (byte)p;
	        }
	    }
	    return out;
	}


}
