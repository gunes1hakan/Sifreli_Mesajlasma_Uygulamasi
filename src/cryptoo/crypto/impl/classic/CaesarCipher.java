package cryptoo.crypto.impl.classic;

import cryptoo.crypto.api.TextCipher;
import cryptoo.crypto.util.CryptoHelpers;

public class CaesarCipher implements TextCipher {
    @Override
    public String algoCode() {
        return "CAESAR";
    }

    @Override
    public String encrypt(String plain, String key) {
        int shift = CryptoHelpers.parseIntSafe(key, 0);
        return caesarEncrypt(plain, shift);
    }

    @Override
    public String decrypt(String cipher, String key) {
        int shift = CryptoHelpers.parseIntSafe(key, 0);
        return caesarEncrypt(cipher, -shift);
    }

    private String caesarEncrypt(String text, int shift) {
        StringBuilder out = new StringBuilder(text.length());
        int n = CryptoHelpers.TR_ALPHABET.length();
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            char u = CryptoHelpers.safeChar(c);
            int idx = CryptoHelpers.alphaIndex(u);
            if (idx >= 0) {
                int ni = (idx + (shift % n) + n) % n;
                out.append(CryptoHelpers.TR_ALPHABET.charAt(ni));
            } else
                out.append(c);
        }
        return out.toString();
    }
}
