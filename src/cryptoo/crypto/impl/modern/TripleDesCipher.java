package cryptoo.crypto.impl.modern;

import cryptoo.crypto.api.TextCipher;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class TripleDesCipher implements TextCipher {

    @Override
    public String algoCode() {
        return cryptoo.CryptoUtils.ALGO_3DES;
    }

    @Override
    public String encrypt(String plain, String keyStr) throws Exception {
        if (keyStr == null || keyStr.isEmpty())
            throw new IllegalArgumentException("3DES key gerekli");
        byte[] k = keyStr.getBytes(StandardCharsets.UTF_8);
        byte[] k24 = new byte[24];
        for (int i = 0; i < 24; i++)
            k24[i] = (i < k.length) ? k[i] : 0;

        SecretKey key = new SecretKeySpec(k24, "DESede");
        Cipher c = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, key);
        byte[] ct = c.doFinal(plain.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(ct);
    }

    @Override
    public String decrypt(String cipherText, String keyStr) throws Exception {
        if (keyStr == null || keyStr.isEmpty())
            throw new IllegalArgumentException("3DES key gerekli");
        byte[] k = keyStr.getBytes(StandardCharsets.UTF_8);
        byte[] k24 = new byte[24];
        for (int i = 0; i < 24; i++)
            k24[i] = (i < k.length) ? k[i] : 0;

        SecretKey key = new SecretKeySpec(k24, "DESede");
        Cipher c = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        c.init(Cipher.DECRYPT_MODE, key);
        byte[] pt = c.doFinal(Base64.getDecoder().decode(cipherText));
        return new String(pt, StandardCharsets.UTF_8);
    }
}
