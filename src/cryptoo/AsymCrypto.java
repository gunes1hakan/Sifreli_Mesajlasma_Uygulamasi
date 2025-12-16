package cryptoo;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.engines.ElGamalEngine;
import org.bouncycastle.crypto.generators.ElGamalKeyPairGenerator;
import org.bouncycastle.crypto.generators.ElGamalParametersGenerator;
import org.bouncycastle.crypto.params.ElGamalKeyGenerationParameters;
import org.bouncycastle.crypto.params.ElGamalParameters;
import org.bouncycastle.crypto.params.ElGamalPrivateKeyParameters;
import org.bouncycastle.crypto.params.ElGamalPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public final class AsymCrypto {

    static {
        BCConfig.init();
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private AsymCrypto() {}

    // ================= RSA (encrypt/decrypt) =================
    public static KeyPair rsaGenerate() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        return gen.generateKeyPair();
    }

    public static String rsaEncryptB64(PublicKey pk, byte[] data) throws Exception {
        Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        c.init(Cipher.ENCRYPT_MODE, pk);
        return Base64.getEncoder().encodeToString(c.doFinal(data));
    }

    public static byte[] rsaDecryptB64(PrivateKey sk, String ctB64) throws Exception {
        Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        c.init(Cipher.DECRYPT_MODE, sk);
        return c.doFinal(Base64.getDecoder().decode(ctB64));
    }

    // ================= DSA (sign/verify) =================
    public static KeyPair dsaGenerate() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("DSA");
        gen.initialize(2048);
        return gen.generateKeyPair();
    }

    public static String dsaSignB64(PrivateKey sk, String message) throws Exception {
        Signature sig = Signature.getInstance("SHA256withDSA");
        sig.initSign(sk);
        sig.update(message.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(sig.sign());
    }

    public static boolean dsaVerify(PublicKey pk, String message, String sigB64) throws Exception {
        Signature sig = Signature.getInstance("SHA256withDSA");
        sig.initVerify(pk);
        sig.update(message.getBytes(StandardCharsets.UTF_8));
        return sig.verify(Base64.getDecoder().decode(sigB64));
    }

    // ================= DH (key agreement) =================
    public static KeyPair dhGenerate() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("DH");
        gen.initialize(2048);
        return gen.generateKeyPair();
    }

    public static String dhDeriveSharedKeyB64(PrivateKey myPriv, PublicKey theirPub) throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance("DH");
        ka.init(myPriv);
        ka.doPhase(theirPub, true);
        byte[] secret = ka.generateSecret();
        // Pratik: secret’i direkt kullanma; hashleyip 32 byte üret
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] key = md.digest(secret);
        return Base64.getEncoder().encodeToString(key);
    }

    // ================= ECC (ECDH key agreement) =================
    public static KeyPair ecdhGenerate() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
        gen.initialize(new ECGenParameterSpec("secp256r1"));
        return gen.generateKeyPair();
    }

    public static String ecdhDeriveSharedKeyB64(PrivateKey myPriv, PublicKey theirPub) throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(myPriv);
        ka.doPhase(theirPub, true);
        byte[] secret = ka.generateSecret();
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] key = md.digest(secret);
        return Base64.getEncoder().encodeToString(key);
    }

    // ================= ElGamal (BC) encrypt/decrypt =================
    // Not: ElGamal "mesaj şifreleme" için kullanılabilir ama pratikte hibrit kullanılır.
    public static AsymmetricCipherKeyPair elgamalGenerateKeyPair() {
        ElGamalParametersGenerator pGen = new ElGamalParametersGenerator();
        pGen.init(2048, 20, new SecureRandom());
        ElGamalParameters params = pGen.generateParameters();

        ElGamalKeyPairGenerator gen = new ElGamalKeyPairGenerator();
        gen.init(new ElGamalKeyGenerationParameters(new SecureRandom(), params));
        return gen.generateKeyPair();
    }

    public static String elgamalEncryptB64(ElGamalPublicKeyParameters pub, byte[] data) throws Exception {
        ElGamalEngine eng = new ElGamalEngine();
        eng.init(true, new ParametersWithRandom(pub, new SecureRandom()));
        byte[] ct = eng.processBlock(data, 0, data.length);
        return Base64.getEncoder().encodeToString(ct);
    }

    public static byte[] elgamalDecryptB64(ElGamalPrivateKeyParameters priv, String ctB64) throws Exception {
        byte[] ct = Base64.getDecoder().decode(ctB64);
        ElGamalEngine eng = new ElGamalEngine();
        eng.init(false, priv);
        return eng.processBlock(ct, 0, ct.length);
    }
}
