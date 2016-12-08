package crypto;
import java.io.IOException;
import java.security.GeneralSecurityException;

import javax.crypto.SecretKey;

public class Main {

	public static void main(String[] args) {
		char passwd[] = "azerty".toCharArray();
		RSAKeyGenerator rsaKG = new RSAKeyGenerator();
		try {
			KeyStoreManager ksm = new KeyStoreManager("JCEKS","yolo.ks",passwd);
			ksm.importPrivateKey(rsaKG.getRSAPrivatecKey(), "max",passwd);
		} catch (GeneralSecurityException | IOException e) {
			e.printStackTrace();
		}
		
	}
}
