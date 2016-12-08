package crypto;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;

public class RSAKeyGenerator {
	public PrivateKey getRSAPrivatecKey(){
		// Création d'un générateur RSA
		KeyPairGenerator generateurCles = null;
		try {
		    generateurCles = KeyPairGenerator.getInstance("RSA");
		    generateurCles.initialize(2048);
		} catch(NoSuchAlgorithmException e) {
		    System.err.println("Erreur lors de l'initialisation du générateur de clés : " + e);
		    System.exit(-1);
		}
		KeyPair paireCles = generateurCles.generateKeyPair();
		return(paireCles.getPrivate());
	}
}
