import io.jsonwebtoken.Jwts;

import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.crypto.MacProvider;
import io.jsonwebtoken.impl.crypto.RsaProvider;

import java.io.IOException;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class Generator {
    /**
     * Generates a jwt from a given JKS keystore and alias
     * 
     * @param keyStoreName The filename of the keystore to load
     * @param password The password used to access the keystore
     * @param alias The alias used to look up the private key + cert in the store
     * 
     * @return A string representing the jwt created
     * @throws IOException If the keystore file cannot be loaded
     * @throws NoSuchAlgorithmException If the digest needed to calculate the cert finger print cannot be found
     * @throws CertificateEncodingException If the certificate loaded from the JKS cannot be encoded
     */
    public String generateJwt(String keyStoreName, char[] password, String alias) throws IOException, NoSuchAlgorithmException, CertificateEncodingException {
    	JksLoader loader = new JksLoader();
    	
    	PrivateKeyEntry privateKeyEntry = loader.loadPrivateEntry(keyStoreName, password, alias);

		String s = Jwts.builder()
				.setHeaderParams(getHeaderParams())
				.setClaims(getClaims())
				.signWith(SignatureAlgorithm.RS256, privateKeyEntry.getPrivateKey())
				.compact();
        
        return s;
    }

	private Map<String, Object> getClaims() {
    	ConcurrentHashMap<String, Object> claims = new ConcurrentHashMap<>();
    	
    	return claims;
    }
	
	private Map<String, Object> getHeaderParams() {
		ConcurrentHashMap<String, Object> headerParams = new ConcurrentHashMap<>();
		
		return headerParams;
	}
}
