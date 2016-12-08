import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.security.auth.x500.X500Principal;

/**
 * Classe pr�sentant des m�thodes permettant la manipulation ais�e des keystores.
 * @author Julien Lepagnot
 */
public class KeyStoreTools {

    // Le keystore de l'instance
    private KeyStore ks;

    // Le mot de passe du keystore
    private char[] storepass;
    
    /**
     * Construction d'une instance de la classe.
     * @param type Le type du keystore
     * @param file Le fichier contenant le keystore
     * @param passwd Le mot de passe du keystore
     */
    public KeyStoreTools(String type, File file, char[] passwd)
            throws GeneralSecurityException, IOException {
        // Construction d'une instance d'un keystore de type type
        ks = KeyStore.getInstance(type);
        // Initialisation du keystore avec le contenu du fichier file
        InputStream is = new BufferedInputStream(new FileInputStream(file));
        ks.load(is, passwd);
        // Il faut garder le mot de passe du keystore pour l'utiliser par d�faut
        // lorsque l'utilisateur de la classe ne pr�cise pas de mot de passe
        // pour ins�rer une nouvelle entr�e dans le keystore de l'instance
        // (la seule m�thode concern�e est importSecretKey)
        storepass = passwd;
    }

    /**
     * Construction d'une instance de la classe.
     * @param type Le type du keystore
     * @param file Le nom du fichier contenant le keystore
     * @param passwd Le mot de passe du keystore
     */
    public KeyStoreTools(String type, String fileName, char[] passwd)
            throws GeneralSecurityException, IOException {
        this(type, new File(fileName), passwd);
    }

    /**
     * Renvoie un String donnant une description de la cl� publique key selon
     * un format d�pendant de son algorithme (RSA ou DSA)
     * @param key Une cl� publique
     */
    public static String toString(PublicKey key) {
        StringBuilder sb = new StringBuilder();
        // Pr�sente le type de cl�
        sb.append("Cl� publique de type : ").append(key.getAlgorithm()).append('\n');
        if (key instanceof RSAPublicKey) {
            // Cas d'une cl� RSA
            RSAPublicKey rsaPk = (RSAPublicKey)key;
            sb.append("Module de chiffrement :\n");
            sb.append(rsaPk.getModulus()).append('\n');
            sb.append("Exposant public :\n");
            sb.append(rsaPk.getPublicExponent()).append('\n');
        } else if (key instanceof DSAPublicKey) {
            // Cas d'une cl� DSA
            DSAPublicKey dsaPk = (DSAPublicKey)key;
            DSAParams dsaParams = dsaPk.getParams();
            sb.append("Param�tres globaux :\n");
            sb.append("P : ").append(dsaParams.getP()).append('\n');
            sb.append("Q : ").append(dsaParams.getQ()).append('\n');
            sb.append("G : ").append(dsaParams.getG()).append('\n');
            sb.append("Cl� publique :\n");
            sb.append("Y : ").append(dsaPk.getY());
        } else {
            // Cas non pris en charge
            throw new IllegalArgumentException("Cl� de type non trait�");
        }
        // Retourne la chaine construite, d�crivant la cl�
        return sb.toString();
    }

    /**
     * Renvoie un String donnant une description de la cl� priv�e key selon
     * un format d�pendant de son algorithme (RSA ou DSA).
     * @param key Une cl� priv�e
     */
    public static String toString(PrivateKey key) {
        StringBuilder sb = new StringBuilder();
        // Pr�sente le type de cl�
        sb.append("Cl� priv�e de type : ").append(key.getAlgorithm()).append('\n');
        if (key instanceof RSAPrivateKey) {
            // Cas d'une cl� RSA
            RSAPrivateKey rsaPrk = (RSAPrivateKey)key;
            sb.append("Module de chiffrement :\n");
            sb.append(rsaPrk.getModulus()).append('\n');
            sb.append("Exposant priv� :\n");
            sb.append(rsaPrk.getPrivateExponent()).append('\n');
        } else if (key instanceof DSAPrivateKey) {
            // Cas d'une cl� DSA
            DSAPrivateKey dsaPrk = (DSAPrivateKey)key;
            DSAParams dsaParams = dsaPrk.getParams();
            sb.append("Param�tres globaux :\n");
            sb.append("P : ").append(dsaParams.getP()).append('\n');
            sb.append("Q : ").append(dsaParams.getQ()).append('\n');
            sb.append("G : ").append(dsaParams.getG()).append('\n');
            sb.append("Cl� priv�e :\n");
            sb.append("X : ").append(dsaPrk.getX());
        } else {
            // Cas non pris en charge
            throw new IllegalArgumentException("Cl� de type non trait�");
        }
        // Retourne la chaine construite, d�crivant la cl�
        return sb.toString();
    }

    /**
     * Renvoie un String d�crivant la liste des descriptions des cl�s priv�es
     * contenues dans le keystore de l'instance.
     * @param passwd Le mot de passe des cl�s priv�es.
     */
    public String listPrivateKeys(char[] passwd)
            throws GeneralSecurityException {
        StringBuilder sb = new StringBuilder();
        // R�cup�re tous les alias identifiant les entr�es du keystore
        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            // Teste si l'entr�e nomm�e par l'alias courant est une cl� priv�e
            if (ks.entryInstanceOf(alias, KeyStore.PrivateKeyEntry.class)) {
                // Si c'est le cas, pr�senter l'alias du certificat...
                sb.append("Alias : ").append(alias).append('\n');
                // ...puis la r�cup�rer
                PrivateKey key;
                try {
                    key = (PrivateKey)ks.getKey(alias, passwd);
                    // D�crit la cl� priv�e
                    sb.append(toString(key));
                }
                catch (UnrecoverableKeyException ex) {
                    // Cas o� la cl� ne peut �tre r�cup�r�e (mot de passe invalide...)
                    sb.append("Cl� priv�e non r�cup�rable : ").append(ex.getLocalizedMessage()).append('\n');
                }
                sb.append('\n');
            }
        }
        // Retourne la chaine construite, d�crivant les cl�s priv�es du keystore
        return sb.toString();
    }

    /**
     * Ins�re dans le keystore manipul� une cl� secr�te key identifi� par le nom
     * alias et �ventuellement prot�g� par le mot de passe optionnel passwd.
     * @param key La cl� secr�te � ins�rer.
     * @param alias L'alias � associer avec la cl� ins�r�e.
     * @param passwd Le mot de passe �ventuel pour prot�ger la cl�.
     */
    public void importSecretKey(SecretKey key, String alias, char[] passwd)
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
     * Sauvegarde l'�tat courant du keystore manipul� dans le fichier file en le
     * prot�geant avec le mot de passe passwd.
     * @param file Le fichier dans lequel sauvegarder le keystore de l'instance.
     * @param passwd Le mot de passe prot�geant le fichier cr��.
     */
    public void save(File file, char[] passwd)
            throws GeneralSecurityException, IOException {
        // S�rialise le contenu du keystore dans le flot attach� au fichier file
        try (OutputStream os = new BufferedOutputStream(new FileOutputStream(file))) {
            ks.store(os, passwd);
        }
    }

    /**
     * D�monstration de la classe.
     * @param args
     */
    /*public static void main(String[] args) {
        try {
            // Nouvelle instance de la classe initialis�e avec le fichier store.ks
            KeyStoreTools kst = new KeyStoreTools("JCEKS", "exemple.ks", "mdpKeystore".toCharArray());

            // Liste les certificats et cl�s priv�es du keystore
            System.out.println(kst.listCertificates());
            System.out.println(kst.listPrivateKeys("mdpKeystore".toCharArray()));
            System.out.println(kst.listPrivateKeys("mdpKeys".toCharArray()));

            // Obtient une instance d'un g�n�rateur de cl�s secr�tes pour l'AES
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            // Sp�cifie la longueur de la cl� (128 bits)
            kg.init(128);
            // G�n�re la cl�
            SecretKey key = kg.generateKey();
            // Ins�re la cl� dans le keystore en lui associant l'alias key6
            kst.importSecretKey(key, "key6", null);

            // Ins�re le certificat msca.cer en lui associant l'alias key7
            kst.importCertificates(new File("msca.cer"), new String[]{"key7"});

            // Sauvegarde le keystore dans le fichier kstore.ks avec un nouveau mot de passe
            kst.save(new File("kstore.ks"), "x75DT7Rdx98tdZK".toCharArray());

            // Nouvelle instance de la classe initialis�e avec le fichier kstore.ks
            kst = new KeyStoreTools("JCEKS", "kstore.ks", "x75DT7Rdx98tdZK".toCharArray());

            // Liste les certificats et cl�s priv�es du nouveau keystore
            System.out.println(kst.listCertificates());
            System.out.println(kst.listPrivateKeys("td3exo1".toCharArray()));
        } catch (GeneralSecurityException | IOException ex) {
            Logger.getLogger(KeyStoreTools.class.getName()).log(Level.SEVERE, null, ex);
        }
    }*/
}

