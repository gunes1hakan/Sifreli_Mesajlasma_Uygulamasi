package cryptoo.crypto.impl.modern;

import cryptoo.crypto.api.TextCipher;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class BlowfishCipher implements TextCipher {

    @Override
    public String algoCode() {
        return cryptoo.CryptoUtils.ALGO_BLOWFISH;
    }

    @Override
    public String encrypt(String plain, String keyStr) throws Exception {
        if (keyStr == null || keyStr.isEmpty())
            throw new IllegalArgumentException("Blowfish key gerekli");
        byte[] k = keyStr.getBytes(StandardCharsets.UTF_8);
        SecretKey key = new SecretKeySpec(k, "Blowfish");
        Cipher c = Cipher.getInstance("Blowfish/ECB/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, key);
        byte[] ct = c.doFinal(plain.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(ct);
    }

    @Override
    public String decrypt(String cipherText, String keyStr) throws Exception {
        if (keyStr == null || keyStr.isEmpty())
            throw new IllegalArgumentException("Blowfish key gerekli");
        byte[] k = keyStr.getBytes(StandardCharsets.UTF_8);
        SecretKey key = new SecretKeySpec(k, "Blowfish");
        Cipher c = Cipher.getInstance("Blowfish/ECB/PKCS5Padding");
        c.init(Cipher.DECRYPT_MODE, key);
        byte[] pt = c.doFinal(Base64.getDecoder().decode(cipherText));
        return new String(pt, StandardCharsets.UTF_8);
    }
}
