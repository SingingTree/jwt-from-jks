import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

/**
 * Loads keys and certs from JKS
 */

public class JksLoader {
    public KeyStore.PrivateKeyEntry loadPrivateEntry(String keyStoreName, char[] password, String alias) throws IOException {
        KeyStore ks;
        try {
            ks = KeyStore.getInstance(KeyStore.getDefaultType());
        } catch (KeyStoreException e) {
            throw new IllegalStateException(e);
        }

        try(FileInputStream fis = new FileInputStream(keyStoreName)) {
            ks.load(fis, password);
        } catch (CertificateException e) {
            throw new IllegalStateException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }

        KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(password);

        // Get private key
        KeyStore.PrivateKeyEntry pkEntry;
        try {
            pkEntry = (KeyStore.PrivateKeyEntry) ks.getEntry(alias, protParam);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        } catch (UnrecoverableEntryException e) {
            throw new IllegalStateException(e);
        } catch (KeyStoreException e) {
            throw new IllegalStateException(e);
        }

        return pkEntry;
    }
}
