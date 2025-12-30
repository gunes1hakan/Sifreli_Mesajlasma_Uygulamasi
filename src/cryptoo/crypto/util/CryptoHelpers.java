package cryptoo.crypto.util;

public class CryptoHelpers {
    public static final String TR_ALPHABET = "ABCÇDEFGĞHIİJKLMNOÖPRSŞTUÜVYZ";

    public static boolean isTrLetter(char ch) {
        char u = Character.toUpperCase(ch);
        return TR_ALPHABET.indexOf(u) >= 0;
    }

    public static char safeChar(char ch) {
        if (isTrLetter(ch))
            return Character.toUpperCase(ch);
        return ch;
    }

    public static String normalizeText(String s, boolean lettersOnly) {
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

    public static int alphaIndex(char u) {
        return TR_ALPHABET.indexOf(u);
    }

    public static int parseIntSafe(String s, int def) {
        try {
            if (s == null)
                return def;
            return Integer.parseInt(s.trim());
        } catch (Exception e) {
            return def;
        }
    }
}
