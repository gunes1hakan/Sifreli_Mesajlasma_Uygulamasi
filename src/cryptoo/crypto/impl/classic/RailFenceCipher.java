package cryptoo.crypto.impl.classic;

import cryptoo.crypto.api.TextCipher;
import cryptoo.crypto.util.CryptoHelpers;

public class RailFenceCipher implements TextCipher {
    @Override
    public String algoCode() {
        return "RAILFENCE";
    }

    @Override
    public String encrypt(String plain, String key) {
        int rails = CryptoHelpers.parseIntSafe(key, 2);
        return railFenceEncrypt(plain, rails);
    }

    @Override
    public String decrypt(String cipher, String key) {
        int rails = CryptoHelpers.parseIntSafe(key, 2);
        return railFenceDecrypt(cipher, rails);
    }

    private String railFenceEncrypt(String text, int numRails) {
        if (numRails < 2)
            return text;
        StringBuilder[] rails = new StringBuilder[numRails];
        for (int i = 0; i < numRails; i++)
            rails[i] = new StringBuilder();

        int row = 0;
        int dir = 1; // 1 down, -1 up
        for (int i = 0; i < text.length(); i++) {
            rails[row].append(text.charAt(i));
            if (row == 0)
                dir = 1;
            else if (row == numRails - 1)
                dir = -1;
            row += dir;
        }

        StringBuilder out = new StringBuilder();
        for (StringBuilder sb : rails)
            out.append(sb);
        return out.toString();
    }

    private String railFenceDecrypt(String cipher, int numRails) {
        if (numRails < 2)
            return cipher;
        int n = cipher.length();
        // Determine lengths of each rail
        int[] railLens = new int[numRails];
        int row = 0;
        int dir = 1;
        for (int i = 0; i < n; i++) {
            railLens[row]++;
            if (row == 0)
                dir = 1;
            else if (row == numRails - 1)
                dir = -1;
            row += dir;
        }

        // Split cipher into rails
        String[] railsData = new String[numRails];
        int current = 0;
        for (int i = 0; i < numRails; i++) {
            railsData[i] = cipher.substring(current, current + railLens[i]);
            current += railLens[i];
        }

        // Reconstruct
        StringBuilder pt = new StringBuilder();
        int[] cursors = new int[numRails];
        row = 0;
        dir = 1;
        for (int i = 0; i < n; i++) {
            pt.append(railsData[row].charAt(cursors[row]++));
            if (row == 0)
                dir = 1;
            else if (row == numRails - 1)
                dir = -1;
            row += dir;
        }
        return pt.toString();
    }
}
