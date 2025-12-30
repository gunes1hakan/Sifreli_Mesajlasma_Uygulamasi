package cryptoo.crypto.impl.modern;

import cryptoo.crypto.api.TextCipher;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class DesEcbCipherBc implements TextCipher {

    @Override
    public String algoCode() {
        return cryptoo.CryptoUtils.ALGO_DES_BC;
    }

    @Override
    public String encrypt(String plain, String key) throws Exception {
        if (key == null || key.isEmpty()) {
            throw new IllegalArgumentException("DES için en az 8 karakterlik anahtar gir.");
        }
        byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
        byte[] k8 = new byte[8];
        for (int i = 0; i < 8; i++) {
            k8[i] = (i < keyBytes.length) ? keyBytes[i] : 0;
        }
        SecretKeySpec sk = new SecretKeySpec(k8, "DES");
        Cipher c = Cipher.getInstance("DES/ECB/PKCS5Padding", "BC");
        c.init(Cipher.ENCRYPT_MODE, sk);
        byte[] ct = c.doFinal(plain.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(ct);
    }

    @Override
    public String decrypt(String cipherText, String key) throws Exception {
        if (key == null || key.isEmpty()) {
            throw new IllegalArgumentException("DES için en az 8 karakterlik anahtar gir.");
        }
        byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
        byte[] k8 = new byte[8];
        for (int i = 0; i < 8; i++) {
            k8[i] = (i < keyBytes.length) ? keyBytes[i] : 0;
        }
        SecretKeySpec sk = new SecretKeySpec(k8, "DES");
        Cipher c = Cipher.getInstance("DES/ECB/PKCS5Padding", "BC");
        c.init(Cipher.DECRYPT_MODE, sk);
        byte[] ct = Base64.getDecoder().decode(cipherText);
        byte[] pt = c.doFinal(ct);
        return new String(pt, StandardCharsets.UTF_8);
    }
}
