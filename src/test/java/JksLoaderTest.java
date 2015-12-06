import io.jsonwebtoken.impl.crypto.RsaProvider;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.*;

public class JksLoaderTest {
    public static final String TEST_KEY_STORE_FILENAME = "testKeyStore.jks";

    @Rule
    public TemporaryFolder testFolder = new TemporaryFolder();

    @Test
    public void testLoadKey() throws IOException, GeneralSecurityException {
        TestUtils utils = new TestUtils();

        KeyPair keyPair = RsaProvider.generateKeyPair(2048);
        X509Certificate cert = utils.generateCertificate("CN=Test, L=London, C=GB", keyPair, 365, "SHA256withRSA");
        File testKeyStore = testFolder.newFile(TEST_KEY_STORE_FILENAME);
        utils.createTestKeyStore(
                new FileOutputStream(testKeyStore),
                keyPair.getPrivate(),
                cert);

        JksLoader loader = new JksLoader();

        KeyStore.PrivateKeyEntry privateKeyEntry =
                loader.loadPrivateEntry(
                        testKeyStore.getAbsolutePath(),
                        TestUtils.TEST_PASSWORD.toCharArray(),
                        TestUtils.TEST_ALIAS
                );

        assert privateKeyEntry.getCertificate().equals(cert);
        assert privateKeyEntry.getPrivateKey().equals(keyPair.getPrivate());
    }
}
