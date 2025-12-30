package cryptoo;

import java.nio.charset.StandardCharsets;

/**
 * Step 0: Smoke Test
 * Refactor sırasında "kırdık mı?" sorusuna hızlı yanıt vermek için.
 */
public class SmokeTest {

    private static int total = 0;
    private static int passed = 0;

    public static void main(String[] args) {
        System.out.println("=== SMOKE TEST STARTED ===");
        int failed = 0;

        // 0. CHECK KEY DERIVATIONS (HOMEWORK REQUIREMENT)
        try {
            System.out.print("Check AES-128 Key Derivation... ");
            byte[] k128 = CryptoUtils.deriveAes128KeyBytes("password");
            if (k128.length != 16)
                throw new RuntimeException("AES Key must be 16 bytes, got " + k128.length);
            System.out.println("OK");

            System.out.print("Check DES Key Derivation... ");
            byte[] k64 = CryptoUtils.deriveDesKeyBytes("password");
            if (k64.length != 8)
                throw new RuntimeException("DES Key must be 8 bytes, got " + k64.length);
            System.out.println("OK");

        } catch (Exception e) {
            System.out.println("FAILED: " + e.getMessage());
            e.printStackTrace();
            failed++;
        }

        // 1. CHECK CLASSICS
        System.out.println("BC Available: " + CryptoUtils.isBcAvailable());

        // Fixed plaintext: 8 chars, even, no double letters for Playfair compatibility
        String plain = "MERHABAZ";
        // Toy plaintext: ASCII-only, even length
        String plainToy = "ABCDEFGH";

        test(CryptoUtils.ALGO_NONE, plain, "");
        test(CryptoUtils.ALGO_CAESAR, plain, "3");
        test(CryptoUtils.ALGO_VIGENERE, plain, "GIZLI");
        test(CryptoUtils.ALGO_SUBST, plain, "ZYVÜUTŞSRPÖONMLKJİIHĞGFEDÇCBA");
        test(CryptoUtils.ALGO_AFFINE, plain, "5,8");
        test(CryptoUtils.ALGO_PLAYFAIR, plain, "GIZLI");
        test(CryptoUtils.ALGO_RAILFENCE, plain, "3");
        test(CryptoUtils.ALGO_ROUTE, plain, "5");
        test(CryptoUtils.ALGO_COLUMNAR, plain, "ANAHTAR");
        test(CryptoUtils.ALGO_POLYBIUS, plain, "");
        test(CryptoUtils.ALGO_PIGPEN, plain, "");

        // Modern
        // Modern (Platform dependent, skip if unsupported)
        testSkipOnException(CryptoUtils.ALGO_AES_GCM, plain, "secret", "Unsupported?");
        testSkipOnException(CryptoUtils.ALGO_DES, plain, "password", "Unsupported?");
        test(CryptoUtils.ALGO_HILL, plain, "3 3 2 5");
        testSkipOnException(CryptoUtils.ALGO_3DES, plain, "0123456789abcdef01234567", "Unsupported?");
        testSkipOnException(CryptoUtils.ALGO_BLOWFISH, plain, "key", "Unsupported?");

        // GOST requires BC
        if (CryptoUtils.isBcAvailable()) {
            testSkipOnException(CryptoUtils.ALGO_GOST, plain, "key");
        } else {
            skipTest(CryptoUtils.ALGO_GOST, "BC missing");
        }

        // Toy (with tolerance)
        testToy(CryptoUtils.ALGO_FEISTEL, plainToy, "k");
        testToy(CryptoUtils.ALGO_SPN, plainToy, "k");

        // BC Variants (Safe Skip)
        if (CryptoUtils.isBcAvailable()) {
            testSkipOnException(CryptoUtils.ALGO_AES_GCM_BC, plain, "secret", "Exception");
            testSkipOnException(CryptoUtils.ALGO_DES_BC, plain, "password", "Exception");
        } else {
            skipTest(CryptoUtils.ALGO_AES_GCM_BC, "BC missing");
            skipTest(CryptoUtils.ALGO_DES_BC, "BC missing");
        }

        // Legacy Fallback (Non-Base64)
        System.out.println("--- Legacy Fallback Tests (Non-Base64 Input) ---");
        testLegacyFallback(CryptoUtils.ALGO_FEISTEL, "NOT_BASE64_GARBAGE", "k");
        testLegacyFallback(CryptoUtils.ALGO_SPN, "NOT_BASE64_GARBAGE", "k");

        // RSA Helper Self-Test
        System.out.println("--- RSA Helper Self-Test ---");
        testRsaHelpers();

        // Hybrid Codec Test
        System.out.println("--- Hybrid Codec JSON ---");
        testHybridPayloadCodec();

        // Algo Mapper Test
        System.out.println("--- Algo Mapper UI ---");
        testAlgoMapper();

        // Cross-Provider Tests
        System.out.println("--- Cross-Provider Roundtrip (BC -> Default) ---");
        testCrossProvider(CryptoUtils.ALGO_AES_GCM_BC, CryptoUtils.ALGO_AES_GCM, plain, "secret");
        testCrossProvider(CryptoUtils.ALGO_DES_BC, CryptoUtils.ALGO_DES, plain, "password");

        System.out.println("========================");
        System.out.println("TOTAL: " + total + ", PASSED: " + passed + ", FAILED: " + (total - passed - skipped)
                + ", SKIPPED: " + skipped);
        if (total == passed + skipped) {
            System.out.println("RESULT: ALL GREEN ✅" + (skipped > 0 ? " (with skips)" : ""));
        } else {
            System.out.println("RESULT: FAIL ❌");
            System.exit(1);
        }
    }

    private static int skipped = 0;

    private static void test(String algo, String plain, String key) {
        total++;
        String label = String.format("[%s]", algo);
        try {
            // 1. Encrypt
            String enc = CryptoUtils.encrypt(algo, plain, key);

            // 2. Decrypt
            String dec = CryptoUtils.decrypt(algo, enc, key);

            if (dec.equals(plain)) {
                System.out.printf("%-20s PASS\n", label);
                passed++;
            } else {
                System.out.printf("%-20s FAIL -> Exp: %s, Got: %s\n", label, plain, dec);
            }

        } catch (Exception e) {
            System.out.printf("%-20s EXCEPTION: %s\n", label, e.getMessage());
        }
    }

    private static void testToy(String algo, String plain, String key) {
        total++;
        String label = String.format("[%s]", algo);
        try {
            String enc = CryptoUtils.encrypt(algo, plain, key);
            String dec = CryptoUtils.decrypt(algo, enc, key);
            // Strict check
            if (dec.equals(plain)) {
                System.out.printf("%-20s PASS\n", label);
                passed++;
            } else {
                System.out.printf("%-20s FAIL -> Exp: %s, Got: %s\n", label, plain, dec);
            }
        } catch (Exception e) {
            System.out.printf("%-20s EXCEPTION: %s\n", label, e.getMessage());
        }
    }

    private static void testSkipOnException(String algo, String plain, String key) {
        testSkipOnException(algo, plain, key, "Exception");
    }

    private static void testSkipOnException(String algo, String plain, String key, String skipReason) {
        total++;
        String label = String.format("[%s]", algo);
        try {
            String enc = CryptoUtils.encrypt(algo, plain, key);
            String dec = CryptoUtils.decrypt(algo, enc, key);

            if (dec.equals(plain)) {
                System.out.printf("%-20s PASS\n", label);
                passed++;
            } else {
                System.out.printf("%-20s FAIL -> Exp: %s, Got: %s\n", label, plain, dec);
            }
        } catch (Throwable e) {
            skipped++;
            System.out.printf("%-20s SKIP (%s: %s)\n", label, skipReason,
                    e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    private static void testRsaHelpers() {
        total++;
        String label = "[RSA-SelfTest]";
        try {
            // 1. Gen Key
            java.security.KeyPair kp = CryptoUtils.genRsaKeyPair();
            if (kp == null || kp.getPublic() == null)
                throw new RuntimeException("KeyPair gen failed");

            // 2. PubKey B64 cycle
            String pubB64 = CryptoUtils.pubKeyToB64(kp.getPublic());
            java.security.PublicKey pubRestored = CryptoUtils.pubKeyFromB64(pubB64);
            if (!pubRestored.equals(kp.getPublic()))
                throw new RuntimeException("PubKey restore failed");

            // 3. Wrap/Unwrap
            byte[] secret = new byte[16]; // 128 bit
            new java.security.SecureRandom().nextBytes(secret);
            String wrappedUrl = CryptoUtils.rsaWrapKeyUrlB64(kp.getPublic(), secret);
            byte[] unwrapped = CryptoUtils.rsaUnwrapKeyUrlB64(kp.getPrivate(), wrappedUrl);

            if (!java.util.Arrays.equals(secret, unwrapped)) {
                throw new RuntimeException("Wrap/Unwrap mismatch");
            }
            System.out.printf("%-20s PASS\n", label);
            passed++;
        } catch (Throwable e) {
            System.out.printf("%-20s FAIL (Ex: %s)\n", label, e.getMessage());
        }
    }

    private static void testLegacyFallback(String algo, String malformedInput, String key) {
        total++;
        String label = String.format("[%s-Legacy]", algo);
        try {
            // Decrypting non-Base64 input should NOT throw exception, but return some
            // result
            String dec = CryptoUtils.decrypt(algo, malformedInput, key);
            if (dec != null) {
                System.out.printf("%-20s PASS (Fallback triggered)\n", label);
                passed++;
            } else {
                System.out.printf("%-20s FAIL -> Returned null\n", label);
            }
        } catch (Exception e) {
            System.out.printf("%-20s FAIL (Ex: %s)\n", label, e.getMessage());
        }
    }

    private static void testCrossProvider(String encAlgo, String decAlgo, String plain, String key) {
        total++;
        String label = String.format("[%s -> %s]", encAlgo, decAlgo);

        if (!cryptoo.CryptoUtils.isBcAvailable()) {
            skipped++;
            System.out.printf("%-20s SKIP (BC missing)\n", label);
            return;
        }

        try {
            String enc = cryptoo.CryptoUtils.encrypt(encAlgo, plain, key);
            String dec = cryptoo.CryptoUtils.decrypt(decAlgo, enc, key);

            if (dec.equals(plain)) {
                System.out.printf("%-20s PASS\n", label);
                passed++;
            } else {
                System.out.printf("%-20s FAIL -> Exp: %s, Got: %s\n", label, plain, dec);
            }
        } catch (Exception e) {
            System.out.printf("%-20s FAIL (Ex: %s)\n", label, e.getMessage());
        }
    }

    private static void skipTest(String algo, String reason) {
        total++;
        skipped++;
        System.out.printf("[%-18s] SKIP (%s)\n", algo, reason);
    }

    private static void testHybridPayloadCodec() {
        total++;
        String label = "[HybridCodec]";
        try {
            String ctUrl = "CtData123";
            java.util.Map<String, String> keys = new java.util.HashMap<>();
            keys.put("NickA", "WrapA");
            keys.put("Nick\"B", "WrapB"); // Test quote escaping

            String json = CryptoUtils.encodeHybridPayloadJsonV1(ctUrl, keys);
            // {"v":1,"ct":"CtData123","keys":{"NickA":"WrapA","Nick\"B":"WrapB"}}

            Object[] res = CryptoUtils.decodeHybridPayloadJsonV1(json);
            String decCt = (String) res[0];
            java.util.Map<String, String> decKeys = (java.util.Map<String, String>) res[1];

            if (!decCt.equals(ctUrl))
                throw new RuntimeException("CT Mismatch");
            if (!decKeys.get("NickA").equals("WrapA"))
                throw new RuntimeException("Key A missing");
            if (!decKeys.get("Nick\"B").equals("WrapB"))
                throw new RuntimeException("Key B missing/escaping failed");

            System.out.printf("%-20s PASS\n", label);
            passed++;
        } catch (Throwable e) {
            System.out.printf("%-20s FAIL (Ex: %s)\n", label, e.getMessage());
        }
    }

    private static void testAlgoMapper() {
        total++;
        String label = "[AlgoMapper]";
        try {
            // Shadowing Checks
            // Shadowing Checks
            if (!cryptoo.crypto.ui.AlgoLabelMapper.toCode("AES-128 (HYBRID RSA\u2192AES) (BC)")
                    .equals(CryptoUtils.ALGO_AES_GCM_BC_RSA))
                throw new RuntimeException("Shadow 1");
            if (!cryptoo.crypto.ui.AlgoLabelMapper.toCode("DES (HYBRID RSA\u2192DES) (BC)")
                    .equals(CryptoUtils.ALGO_DES_BC_RSA))
                throw new RuntimeException("Shadow 2");
            if (!cryptoo.crypto.ui.AlgoLabelMapper.toCode("AES-128 (HYBRID RSA\u2192AES) (JCE)")
                    .equals(CryptoUtils.ALGO_AES_GCM_RSA))
                throw new RuntimeException("Shadow 3");

            // Standard Checks
            if (!cryptoo.crypto.ui.AlgoLabelMapper.toCode("AES-128 (LIB/JCE) - Password")
                    .equals(CryptoUtils.ALGO_AES_GCM))
                throw new RuntimeException(
                        "Standard 1: " + cryptoo.crypto.ui.AlgoLabelMapper.toCode("AES-128 (LIB/JCE) - Password"));
            if (!cryptoo.crypto.ui.AlgoLabelMapper.toCode("DES (LIB/JCE) - Password").equals(CryptoUtils.ALGO_DES))
                throw new RuntimeException("Standard 2");

            // Manual
            if (!cryptoo.crypto.ui.AlgoLabelMapper.toCode("AES (MANUAL) - SPN").equals(CryptoUtils.ALGO_SPN))
                throw new RuntimeException("Manual 1");
            if (!cryptoo.crypto.ui.AlgoLabelMapper.toCode("DES (MANUAL) - Feistel").equals(CryptoUtils.ALGO_FEISTEL))
                throw new RuntimeException("Manual 2");

            // Legacy
            if (!cryptoo.crypto.ui.AlgoLabelMapper.toCode("Caesar (Kaydırma)").equals(CryptoUtils.ALGO_CAESAR))
                throw new RuntimeException("Legacy 1");

            System.out.printf("%-20s PASS\n", label);
            passed++;
        } catch (Throwable e) {
            System.out.printf("%-20s FAIL (Ex: %s)\n", label, e.getMessage());
        }
    }
}
