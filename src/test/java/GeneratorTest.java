import io.jsonwebtoken.*;
import io.jsonwebtoken.impl.crypto.RsaProvider;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.cert.X509Certificate;

import static org.junit.Assert.fail;

public class GeneratorTest {
    @Rule
    public TemporaryFolder testFolder = new TemporaryFolder();

    @Test
    public void testGenerateJwt() throws IOException, GeneralSecurityException {
        TestUtils utils = new TestUtils();

        KeyPair keyPair = RsaProvider.generateKeyPair(2048);
        X509Certificate cert = utils.generateCertificate("CN=Test, L=London, C=GB", keyPair, 365, "SHA256withRSA");
        File testKeyStore = testFolder.newFile(TestUtils.TEST_KEY_STORE_FILENAME);
        utils.createTestKeyStore(
                new FileOutputStream(testKeyStore),
                keyPair.getPrivate(),
                cert
        );

        Generator generator = new Generator();

        String jwtString = generator.generateJwt(
                testKeyStore.getAbsolutePath(),
                TestUtils.TEST_PASSWORD.toCharArray(),
                TestUtils.TEST_ALIAS
        );

        try {
            assert Jwts.parser().setSigningKey(keyPair.getPublic()).parseClaimsJws(jwtString).getBody().get("test", String.class).equals("test");
        } catch (SignatureException e) {
            fail("Couldn't parse generated jwt");
        }
    }
}
