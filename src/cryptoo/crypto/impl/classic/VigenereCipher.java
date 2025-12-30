package cryptoo.crypto.impl.classic;

import cryptoo.crypto.api.TextCipher;
import cryptoo.crypto.util.CryptoHelpers;

public class VigenereCipher implements TextCipher {
    @Override
    public String algoCode() {
        return "VIGENERE";
    }

    @Override
    public String encrypt(String plain, String key) {
        return vigenereEncrypt(plain, key);
    }

    @Override
    public String decrypt(String cipher, String key) {
        return vigenereDecrypt(cipher, key);
    }

    private String vigenereEncrypt(String text, String keyRaw) {
        String textN = CryptoHelpers.normalizeText(text, false);
        String keyN = CryptoHelpers.normalizeText(keyRaw == null ? "" : keyRaw, true);
        if (keyN.isEmpty())
            return textN;
        StringBuilder out = new StringBuilder(textN.length());
        int n = CryptoHelpers.TR_ALPHABET.length(), ki = 0;
        for (int i = 0; i < textN.length(); i++) {
            char c = textN.charAt(i);
            if (!CryptoHelpers.isTrLetter(c)) {
                out.append(c);
                continue;
            }
            char kc = keyN.charAt(ki % keyN.length());
            int s = CryptoHelpers.alphaIndex(kc);
            int ti = CryptoHelpers.alphaIndex(c);
            out.append(CryptoHelpers.TR_ALPHABET.charAt((ti + s) % n));
            ki++;
        }
        return out.toString();
    }

    private String vigenereDecrypt(String cipher, String keyRaw) {
        String cN = CryptoHelpers.normalizeText(cipher, false);
        String keyN = CryptoHelpers.normalizeText(keyRaw == null ? "" : keyRaw, true);
        if (keyN.isEmpty())
            return cN;
        StringBuilder out = new StringBuilder(cN.length());
        int n = CryptoHelpers.TR_ALPHABET.length(), ki = 0;
        for (int i = 0; i < cN.length(); i++) {
            char c = cN.charAt(i);
            if (!CryptoHelpers.isTrLetter(c)) {
                out.append(c);
                continue;
            }
            char kc = keyN.charAt(ki % keyN.length());
            int s = CryptoHelpers.alphaIndex(kc);
            int ci = CryptoHelpers.alphaIndex(c);
            out.append(CryptoHelpers.TR_ALPHABET.charAt((ci - s + n) % n));
            ki++;
        }
        return out.toString();
    }
}
