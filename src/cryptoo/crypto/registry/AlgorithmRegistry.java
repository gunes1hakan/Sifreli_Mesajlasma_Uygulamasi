package cryptoo.crypto.registry;

import cryptoo.crypto.api.TextCipher;
import java.util.HashMap;
import java.util.Map;
import java.util.Collection;
import java.util.Collections;

import cryptoo.crypto.impl.classic.CaesarCipher;
import cryptoo.crypto.impl.classic.VigenereCipher;
import cryptoo.crypto.impl.modern.AesGcmCipher;
import cryptoo.crypto.impl.modern.DesEcbCipher;
import cryptoo.crypto.impl.modern.TripleDesCipher;
import cryptoo.crypto.impl.modern.BlowfishCipher;
import cryptoo.crypto.impl.modern.GostCipher;

public class AlgorithmRegistry {
    private static final Map<String, TextCipher> registry = new HashMap<>();
    private static boolean initialized = false;

    public static void register(TextCipher cipher) {
        if (cipher != null && cipher.algoCode() != null) {
            registry.put(cipher.algoCode(), cipher);
        }
    }

    public static TextCipher get(String algoCode) {
        return registry.get(algoCode);
    }

    public static Collection<TextCipher> all() {
        return Collections.unmodifiableCollection(registry.values());
    }

    public static void registerDefaults() {
        if (initialized)
            return;
        initialized = true;
        try {
            cryptoo.BCConfig.init();
        } catch (Throwable t) {
            System.err.println("Warning: BC provider not available: " + t.getMessage());
        }
        register(new CaesarCipher());
        register(new VigenereCipher());
        register(new cryptoo.crypto.impl.classic.AffineCipher());
        register(new cryptoo.crypto.impl.classic.SubstitutionCipher());
        register(new cryptoo.crypto.impl.classic.RailFenceCipher());
        register(new cryptoo.crypto.impl.classic.PolybiusCipher());

        // Modern
        register(new AesGcmCipher());
        register(new DesEcbCipher());
        register(new TripleDesCipher());
        register(new BlowfishCipher());
        register(new GostCipher());
        // BC Variants
        if (cryptoo.CryptoUtils.isBcAvailable()) {
            try {
                register(new cryptoo.crypto.impl.modern.AesGcmCipherBc());
                register(new cryptoo.crypto.impl.modern.DesEcbCipherBc());
            } catch (Throwable t) {
                System.err.println("Warning: Failed to register BC ciphers: " + t.getMessage());
            }
        }
    }
}
