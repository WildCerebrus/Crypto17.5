package crypto;
import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;

import javax.crypto.SecretKey;

public class KeyStoreManager {
	private KeyStore ks;
	private char[] storepass;
	
	/**
	 * A UTILISER SUR UN KEYSTORE DEJA GENERE
	 * 
	 * Creation du gestionnaire de Keystore
	 * Le type correspond par exemple à RSA ou DSA
	 * Le file correspond au fichier contenant le keystore
	 * Le passwd est le mdp du keystore
	 */
	public KeyStoreManager(String type, File file, char[] passwd)
            throws GeneralSecurityException, IOException {
        // Construction d'une instance d'un keystore de type type
        ks = KeyStore.getInstance(type);
        // Initialisation du keystore avec le contenu du fichier file
        InputStream is = new BufferedInputStream(new FileInputStream(file));
        ks.load(null, passwd);
        // Il faut garder le mot de passe du keystore pour l'utiliser par défaut
        // lorsque l'utilisateur de la classe ne précise pas de mot de passe
        // pour insérer une nouvelle entrée dans le keystore de l'instance
        // (la seule méthode concernée est importSecretKey)
        storepass = passwd;
    }
	
	/**
	 * A UTILISER POUR CREER UN NOUVEAU KEYSTORE
	 * 
	 * Creation du gestionnaire de Keystore
	 * Le type correspond par exemple à RSA ou DSA
	 * Le fileName correspond au nom de fichier contenant le keystore
	 * Le passwd est le mdp du keystore
	 */
	public KeyStoreManager(String type, String fileName, char[] passwd)
            throws GeneralSecurityException, IOException {
        this(type, new File(fileName), passwd);
    }
	
	/**
	 * INSERTION CLE SECRETE DANS LE KEYSTORE
	 * 
     * Insère dans le keystore manipulé une clé privee key identifié par le nom
     * alias et éventuellement protégé par le mot de passe optionnel passwd.
     * @param key La clé secrète à insérer.
     * @param alias L'alias à associer avec la clé insérée.
     * @param passwd Le mot de passe éventuel pour protéger la clé.
     */
    public void importPrivateKey(PrivateKey key, String alias, char[] passwd)
            throws GeneralSecurityException {
        if (passwd == null) {
            // Insère la clé secrète dans le keystore avec le mot de passe du keystore
            ks.setKeyEntry(alias, key, storepass, null);
        }
        else {
            // Insère la clé secrète dans le keystore avec le mot de passe passwd
            ks.setKeyEntry(alias, key, passwd, null);
        }
    }
    
    /**
     * INSERTION CLE PUBLIQUE DANS LE KEYSTORE
     * 
     * Insère dans le keystore manipulé une clé publique key identifié par le nom
     * alias et éventuellement protégé par le mot de passe optionnel passwd.
     * @param key La clé secrète à insérer.
     * @param alias L'alias à associer avec la clé insérée.
     * @param passwd Le mot de passe éventuel pour protéger la clé.
     */
    public void importPublicKey(PublicKey key, String alias, char[] passwd)
            throws GeneralSecurityException {
        if (passwd == null) {
            // Insère la clé publique dans le keystore avec le mot de passe du keystore
            ks.setKeyEntry(alias, key, storepass, null);
        }
        else {
            // Insère la clé publique dans le keystore avec le mot de passe passwd
            ks.setKeyEntry(alias, key, passwd, null);
        }
    }
    
    /**
     * RECUPERATION CLE SECRETE DANS LE KEYSTORE
     * 
     * Recupere dans le keystore manipule une cle secrete key identifié par le nom
     * alias et eventuellement protege par le mot de passe optionnel passwd
     * @throws NoSuchAlgorithmException 
     * @throws KeyStoreException 
     * @throws UnrecoverableKeyException 
     * 
     */
    public PrivateKey getPrivateKey(String alias, char[] passwd) throws GeneralSecurityException{
    	PrivateKey key = null;
    	try{
    		key = (PrivateKey)ks.getKey(alias, passwd);
    	}catch(UnrecoverableKeyException ex){
    		
    	}
    	return key;
    }
    
    /**
     * RECUPERATION CLE PUBLIQUE DANS LE KEYSTORE
     * 
     * Recupere dans le keystore manipule une cle publique key identifié par le nom
     * alias et eventuellement protege par le mot de passe optionnel passwd
     * @throws NoSuchAlgorithmException 
     * @throws KeyStoreException 
     * @throws UnrecoverableKeyException 
     * 
     */
    public PublicKey getPublicKey(String alias, char[] passwd) throws GeneralSecurityException{
    	PublicKey key = null;
    	try{
    		key = (PublicKey)ks.getKey(alias, passwd);
    	}catch(UnrecoverableKeyException ex){
    		
    	}
    	return key;
    }
    
    
}
