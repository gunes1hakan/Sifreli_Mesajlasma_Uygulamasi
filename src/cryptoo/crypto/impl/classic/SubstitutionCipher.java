package cryptoo.crypto.impl.classic;

import cryptoo.crypto.api.TextCipher;
import cryptoo.crypto.util.CryptoHelpers;
import java.util.HashMap;
import java.util.Map;

public class SubstitutionCipher implements TextCipher {
    @Override
    public String algoCode() {
        return "SUBSTITUTION";
    }

    @Override
    public String encrypt(String plain, String key) {
        return substitutionEncryptAuto(plain, key);
    }

    @Override
    public String decrypt(String cipher, String key) {
        return substitutionDecryptAuto(cipher, key);
    }

    private String substitutionEncryptAuto(String text, String key) {
        int[] map = buildSubstitutionMap(key);
        return substitutionApply(text, map, true);
    }

    private String substitutionDecryptAuto(String cipher, String key) {
        int[] map = buildSubstitutionMap(key);
        return substitutionApply(cipher, map, false);
    }

    private int[] buildSubstitutionMap(String key) {
        // key substitution alphabet.
        // TR_ALPHABET length 29.
        String k = CryptoHelpers.normalizeText(key, true);
        Map<Character, Character> dynamicMap = new HashMap<>();

        // Remove duplicates in key
        StringBuilder uniq = new StringBuilder();
        for (int i = 0; i < k.length(); i++) {
            char c = k.charAt(i);
            if (uniq.toString().indexOf(c) < 0)
                uniq.append(c);
        }
        k = uniq.toString();

        // Fill remaining
        StringBuilder full = new StringBuilder(k);
        for (int i = 0; i < CryptoHelpers.TR_ALPHABET.length(); i++) {
            char c = CryptoHelpers.TR_ALPHABET.charAt(i);
            if (full.toString().indexOf(c) < 0)
                full.append(c);
        }

        // Now full should be length 29 (or more if key had weird chars but normalized)
        // Ensure exact length
        String alphabet = CryptoHelpers.TR_ALPHABET;
        // Logic: Plain(i) -> Cipher(i) = full(i)
        // Or Key represents the target alphabet?
        // CryptoUtils logic was: buildSubstitutionMap(key) -> int[]
        // Let's look at legacy logic if needed.
        // Assuming key IS the substitution alphabet or starts it.
        // Standard subst: A->key[0], B->key[1]...

        int[] map = new int[alphabet.length()];
        for (int i = 0; i < alphabet.length(); i++) {
            if (i < full.length()) {
                char target = full.charAt(i);
                map[i] = CryptoHelpers.alphaIndex(target);
            } else {
                map[i] = i; // fallback
            }
        }
        return map;
    }

    private String substitutionApply(String text, int[] map, boolean enc) {
        StringBuilder out = new StringBuilder(text.length());
        int[] inv = new int[map.length];
        if (!enc) {
            for (int i = 0; i < map.length; i++)
                inv[map[i]] = i;
        }

        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            char u = CryptoHelpers.safeChar(c);
            int idx = CryptoHelpers.alphaIndex(u);
            if (idx >= 0) {
                int t = enc ? map[idx] : inv[idx];
                out.append(CryptoHelpers.TR_ALPHABET.charAt(t));
            } else
                out.append(c);
        }
        return out.toString();
    }
}
