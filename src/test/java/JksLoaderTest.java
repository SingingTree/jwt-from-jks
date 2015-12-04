import io.jsonwebtoken.impl.crypto.RsaProvider;
import org.junit.Test;
import sun.security.x509.*;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.Date;

public class JksLoaderTest {
    public static final String TEST_ALIAS = "testAlias";
    public static final String TEST_PASSWORD = "hunter2";
    public static final String TEST_KEY_STORE_FILENAME = "testKeyStore.jks";


    // Cert generation from http://bfo.com/blog/2011/03/08/odds_and_ends_creating_a_new_x_509_certificate.html
    // Warning: usage of sun classes ahoy: possibly undocumented behaviour changes, binding to specific JREs

    /**
     * Create a self-signed X.509 Certificate
     * @param dn the X.509 Distinguished Name, eg "CN=Test, L=London, C=GB"
     * @param pair the KeyPair
     * @param days how many days from now the Certificate is valid for
     * @param algorithm the signing algorithm, eg "SHA1withRSA"
     */
    X509Certificate generateCertificate(String dn, KeyPair pair, int days, String algorithm)
            throws GeneralSecurityException, IOException
    {
        PrivateKey privkey = pair.getPrivate();
        X509CertInfo info = new X509CertInfo();
        Date from = new Date();
        Date to = new Date(from.getTime() + days * 86400000l);
        CertificateValidity interval = new CertificateValidity(from, to);
        BigInteger sn = new BigInteger(64, new SecureRandom());
        X500Name owner = new X500Name(dn);

        info.set(X509CertInfo.VALIDITY, interval);
        info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(sn));
        info.set(X509CertInfo.SUBJECT, owner);
        info.set(X509CertInfo.ISSUER, owner);
        info.set(X509CertInfo.KEY, new CertificateX509Key(pair.getPublic()));
        info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
        AlgorithmId algo = new AlgorithmId(AlgorithmId.md5WithRSAEncryption_oid);
        info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algo));

        // Sign the cert to identify the algorithm that's used.
        X509CertImpl cert = new X509CertImpl(info);
        cert.sign(privkey, algorithm);

        // Update the algorithm, and resign.
        algo = (AlgorithmId)cert.get(X509CertImpl.SIG_ALG);
        info.set(CertificateAlgorithmId.NAME + "." + CertificateAlgorithmId.ALGORITHM, algo);
        cert = new X509CertImpl(info);
        cert.sign(privkey, algorithm);
        return cert;
    }

    @Test
    public void testLoadKey() throws IOException, GeneralSecurityException {
        JksLoader loader = new JksLoader();
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());

        ks.load(null, TEST_PASSWORD.toCharArray());

        KeyPair keyPair = RsaProvider.generateKeyPair(2048);

        X509Certificate cert = generateCertificate("CN=Test, L=London, C=GB", keyPair, 365, "SHA256withRSA");
        Certificate[] certChain = {cert};

        ks.setKeyEntry(TEST_ALIAS, keyPair.getPrivate(), TEST_PASSWORD.toCharArray(), certChain);

        // store away the keystore
        try (FileOutputStream fos = new FileOutputStream(TEST_KEY_STORE_FILENAME)) {
            ks.store(fos, TEST_PASSWORD.toCharArray());
        }

        KeyStore.PrivateKeyEntry privateKeyEntry =
                loader.loadPrivateEntry(TEST_KEY_STORE_FILENAME, TEST_PASSWORD.toCharArray(), TEST_ALIAS);

        assert privateKeyEntry.getCertificate().equals(cert);
        assert privateKeyEntry.getPrivateKey().equals(keyPair.getPrivate());
    }
}
