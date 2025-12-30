package cryptoo.crypto.impl.modern;

import cryptoo.crypto.api.TextCipher;
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

public class AesGcmCipherBc implements TextCipher {

    private static final byte[] FIXED_SALT = "SecureChatFixedSalt".getBytes(StandardCharsets.UTF_8);
    private static final SecureRandom RNG = new SecureRandom();

    @Override
    public String algoCode() {
        return cryptoo.CryptoUtils.ALGO_AES_GCM_BC;
    }

    @Override
    public String encrypt(String plain, String key) throws Exception {
        if (key == null || key.isEmpty()) {
            throw new IllegalArgumentException("AES-GCM için parola veya session key gerekir.");
        }
        byte[] keyBytes = deriveAesKeyBytes(key);
        SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");

        byte[] iv = new byte[12];
        RNG.nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        byte[] ct = cipher.doFinal(plain.getBytes(StandardCharsets.UTF_8));

        String ivB64 = Base64.getEncoder().encodeToString(iv);
        String ctB64 = Base64.getEncoder().encodeToString(ct);
        return ivB64 + ":" + ctB64;
    }

    @Override
    public String decrypt(String cipherText, String key) throws Exception {
        if (key == null || key.isEmpty()) {
            throw new IllegalArgumentException("AES-GCM çözmek için parola veya session key gerekir.");
        }
        String[] parts = cipherText.split(":", 2);
        if (parts.length != 2)
            throw new IllegalArgumentException("AES-GCM kanonik format bozuk.");
        byte[] iv = Base64.getDecoder().decode(parts[0]);
        byte[] ct = Base64.getDecoder().decode(parts[1]);

        byte[] keyBytes = deriveAesKeyBytes(key);
        SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
        byte[] pt = cipher.doFinal(ct);
        return new String(pt, StandardCharsets.UTF_8);
    }

    private byte[] deriveAesKeyBytes(String keyStr) throws Exception {
        String trimmed = keyStr.trim();
        if (looksLikeBase64Key(trimmed)) {
            byte[] raw = Base64.getDecoder().decode(trimmed);
            if (raw.length == 16 || raw.length == 24 || raw.length == 32) {
                return raw;
            }
        }
        // Force 128-bit via CryptoUtils
        return cryptoo.CryptoUtils.deriveAes128KeyBytes(trimmed);
    }

    private boolean looksLikeBase64Key(String s) {
        if (s == null)
            return false;
        s = s.trim();
        if (s.length() < 40)
            return false;
        return s.matches("^[A-Za-z0-9+/=]+$");
    }
}
