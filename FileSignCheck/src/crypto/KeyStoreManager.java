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
	 * Le type correspond par exemple � RSA ou DSA
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
        // Il faut garder le mot de passe du keystore pour l'utiliser par d�faut
        // lorsque l'utilisateur de la classe ne pr�cise pas de mot de passe
        // pour ins�rer une nouvelle entr�e dans le keystore de l'instance
        // (la seule m�thode concern�e est importSecretKey)
        storepass = passwd;
    }
	
	/**
	 * A UTILISER POUR CREER UN NOUVEAU KEYSTORE
	 * 
	 * Creation du gestionnaire de Keystore
	 * Le type correspond par exemple � RSA ou DSA
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
     * Ins�re dans le keystore manipul� une cl� privee key identifi� par le nom
     * alias et �ventuellement prot�g� par le mot de passe optionnel passwd.
     * @param key La cl� secr�te � ins�rer.
     * @param alias L'alias � associer avec la cl� ins�r�e.
     * @param passwd Le mot de passe �ventuel pour prot�ger la cl�.
     */
    public void importPrivateKey(PrivateKey key, String alias, char[] passwd)
            throws GeneralSecurityException {
        if (passwd == null) {
            // Ins�re la cl� secr�te dans le keystore avec le mot de passe du keystore
            ks.setKeyEntry(alias, key, storepass, null);
        }
        else {
            // Ins�re la cl� secr�te dans le keystore avec le mot de passe passwd
            ks.setKeyEntry(alias, key, passwd, null);
        }
    }
    
    /**
     * INSERTION CLE PUBLIQUE DANS LE KEYSTORE
     * 
     * Ins�re dans le keystore manipul� une cl� publique key identifi� par le nom
     * alias et �ventuellement prot�g� par le mot de passe optionnel passwd.
     * @param key La cl� secr�te � ins�rer.
     * @param alias L'alias � associer avec la cl� ins�r�e.
     * @param passwd Le mot de passe �ventuel pour prot�ger la cl�.
     */
    public void importPublicKey(PublicKey key, String alias, char[] passwd)
            throws GeneralSecurityException {
        if (passwd == null) {
            // Ins�re la cl� publique dans le keystore avec le mot de passe du keystore
            ks.setKeyEntry(alias, key, storepass, null);
        }
        else {
            // Ins�re la cl� publique dans le keystore avec le mot de passe passwd
            ks.setKeyEntry(alias, key, passwd, null);
        }
    }
    
    /**
     * RECUPERATION CLE SECRETE DANS LE KEYSTORE
     * 
     * Recupere dans le keystore manipule une cle secrete key identifi� par le nom
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
     * Recupere dans le keystore manipule une cle publique key identifi� par le nom
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
