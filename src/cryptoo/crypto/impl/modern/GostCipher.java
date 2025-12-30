package cryptoo.crypto.impl.modern;

import cryptoo.crypto.api.TextCipher;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class GostCipher implements TextCipher {

    @Override
    public String algoCode() {
        return cryptoo.CryptoUtils.ALGO_GOST;
    }

    @Override
    public String encrypt(String plain, String keyStr) throws Exception {
        if (keyStr == null || keyStr.isEmpty())
            throw new IllegalArgumentException("GOST key gerekli");
        byte[] k = keyStr.getBytes(StandardCharsets.UTF_8);
        // GOST key 32 byte ister; kısaysa pad
        byte[] k32 = new byte[32];
        for (int i = 0; i < 32; i++)
            k32[i] = (i < k.length) ? k[i] : 0;

        SecretKey key = new SecretKeySpec(k32, "GOST28147");
        Cipher c = Cipher.getInstance("GOST28147/ECB/PKCS5Padding", "BC");
        c.init(Cipher.ENCRYPT_MODE, key);
        byte[] ct = c.doFinal(plain.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(ct);
    }

    @Override
    public String decrypt(String cipherText, String keyStr) throws Exception {
        if (keyStr == null || keyStr.isEmpty())
            throw new IllegalArgumentException("GOST key gerekli");
        byte[] k = keyStr.getBytes(StandardCharsets.UTF_8);
        byte[] k32 = new byte[32];
        for (int i = 0; i < 32; i++)
            k32[i] = (i < k.length) ? k[i] : 0;

        SecretKey key = new SecretKeySpec(k32, "GOST28147");
        Cipher c = Cipher.getInstance("GOST28147/ECB/PKCS5Padding", "BC");
        c.init(Cipher.DECRYPT_MODE, key);
        byte[] pt = c.doFinal(Base64.getDecoder().decode(cipherText));
        return new String(pt, StandardCharsets.UTF_8);
    }
}
