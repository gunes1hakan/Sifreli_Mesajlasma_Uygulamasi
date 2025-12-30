package cryptoo.crypto.impl.classic;

import cryptoo.crypto.api.TextCipher;
import cryptoo.crypto.util.CryptoHelpers;

public class AffineCipher implements TextCipher {
    @Override
    public String algoCode() {
        return "AFFINE";
    }

    @Override
    public String encrypt(String plain, String key) {
        return affineEncryptAuto(plain, key);
    }

    @Override
    public String decrypt(String cipher, String key) {
        return affineDecryptAuto(cipher, key);
    }

    private String affineEncryptAuto(String text, String key) {
        int[] ab = parseAB(key);
        return affineEncrypt(text, ab[0], ab[1]);
    }

    private String affineDecryptAuto(String cipher, String key) {
        int[] ab = parseAB(key);
        return affineDecrypt(cipher, ab[0], ab[1]);
    }

    private int[] parseAB(String key) {
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

    private int egcdInv(int a, int m) {
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

    private String affineEncrypt(String text, int a, int b) {
        int n = CryptoHelpers.TR_ALPHABET.length();
        StringBuilder out = new StringBuilder(text.length());
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            char u = CryptoHelpers.safeChar(c);
            int idx = CryptoHelpers.alphaIndex(u);
            if (idx >= 0) {
                int ni = (a * idx + b) % n;
                if (ni < 0)
                    ni += n;
                out.append(CryptoHelpers.TR_ALPHABET.charAt(ni));
            } else
                out.append(c);
        }
        return out.toString();
    }

    private String affineDecrypt(String cipher, int a, int b) {
        int n = CryptoHelpers.TR_ALPHABET.length();
        int ai = egcdInv(a, n);
        StringBuilder out = new StringBuilder(cipher.length());
        for (int i = 0; i < cipher.length(); i++) {
            char c = cipher.charAt(i);
            char u = CryptoHelpers.safeChar(c);
            int idx = CryptoHelpers.alphaIndex(u);
            if (idx >= 0) {
                int ni = (ai * (idx - b)) % n;
                if (ni < 0)
                    ni += n;
                out.append(CryptoHelpers.TR_ALPHABET.charAt(ni));
            } else
                out.append(c);
        }
        return out.toString();
    }
}
