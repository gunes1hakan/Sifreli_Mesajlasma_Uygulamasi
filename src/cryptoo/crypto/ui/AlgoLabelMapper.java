package cryptoo.crypto.ui;

import cryptoo.CryptoUtils;

public class AlgoLabelMapper {
    public static String toCode(String s) {
        if (s == null)
            return CryptoUtils.ALGO_NONE;

        // Specific / Exact matches first (Hybrid & BC) to prevent shadowing
        // Specific / Exact matches first (Hybrid & BC)
        if ("AES-128 (HYBRID RSA\u2192AES) (BC)".equals(s))
            return CryptoUtils.ALGO_AES_GCM_BC_RSA;
        if ("DES (HYBRID RSA\u2192DES) (BC)".equals(s))
            return CryptoUtils.ALGO_DES_BC_RSA;
        if ("AES-128 (HYBRID RSA\u2192AES) (JCE)".equals(s))
            return CryptoUtils.ALGO_AES_GCM_RSA;
        if ("DES (HYBRID RSA\u2192DES) (JCE)".equals(s))
            return CryptoUtils.ALGO_DES_RSA;

        if ("AES-128 (LIB/BC) - Password".equals(s))
            return CryptoUtils.ALGO_AES_GCM_BC;
        if ("DES (LIB/BC) - Password".equals(s))
            return CryptoUtils.ALGO_DES_BC;

        if ("AES-128 (LIB/JCE) - Password".equals(s))
            return CryptoUtils.ALGO_AES_GCM;
        if ("DES (LIB/JCE) - Password".equals(s))
            return CryptoUtils.ALGO_DES;

        // Manual
        if ("DES (MANUAL) - Feistel".equals(s))
            return CryptoUtils.ALGO_FEISTEL;
        if ("AES (MANUAL) - SPN".equals(s))
            return CryptoUtils.ALGO_SPN;

        // Old / Prefixes for backward compat or other variations?
        // Let's keep logic strict for new ones, but maybe fallback for others.

        // Classics & Others
        if (s.startsWith("Caesar"))
            return CryptoUtils.ALGO_CAESAR;
        if (s.startsWith("Vigen"))
            return CryptoUtils.ALGO_VIGENERE;
        if (s.startsWith("Substitution"))
            return CryptoUtils.ALGO_SUBST;
        if (s.startsWith("Affine"))
            return CryptoUtils.ALGO_AFFINE;
        if (s.startsWith("Playfair"))
            return CryptoUtils.ALGO_PLAYFAIR;
        if (s.startsWith("Rail Fence"))
            return CryptoUtils.ALGO_RAILFENCE;
        if (s.startsWith("Route"))
            return CryptoUtils.ALGO_ROUTE;
        if (s.startsWith("Columnar"))
            return CryptoUtils.ALGO_COLUMNAR;
        if (s.startsWith("Polybius"))
            return CryptoUtils.ALGO_POLYBIUS;
        if (s.startsWith("Pigpen"))
            return CryptoUtils.ALGO_PIGPEN;

        // Moderns (Platform dependent or optional in UI)
        if (s.startsWith("GOST"))
            return CryptoUtils.ALGO_GOST;
        if (s.startsWith("Blowfish"))
            return CryptoUtils.ALGO_BLOWFISH;
        if (s.startsWith("3DES"))
            return CryptoUtils.ALGO_3DES;
        if (s.startsWith("Hill"))
            return CryptoUtils.ALGO_HILL;

        return CryptoUtils.ALGO_NONE;
    }
}
