package cryptoo;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;

/**
 * BouncyCastle provider'ı eklemek için ufak yardımcı sınıf.
 * 
 * Proje başında CryptoUtils bunu bir kez çağırıyor.
 */
public final class BCConfig {

    private BCConfig() {
        // Kullanılmıyor, static init var.
    }

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /** Provider'ın yüklenmesini garanti etmek için çağırılır. */
    public static void init() {
        // static bloğu tetikler, ekstra işlem yok.
    }
}
