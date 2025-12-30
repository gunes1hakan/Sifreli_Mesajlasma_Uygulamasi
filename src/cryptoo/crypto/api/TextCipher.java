package cryptoo.crypto.api;

public interface TextCipher {
    String algoCode();

    String encrypt(String plain, String key) throws Exception;

    String decrypt(String cipher, String key) throws Exception;
}
