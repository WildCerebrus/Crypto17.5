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
 * Classe présentant des méthodes permettant la manipulation aisée des keystores.
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
        // Il faut garder le mot de passe du keystore pour l'utiliser par défaut
        // lorsque l'utilisateur de la classe ne précise pas de mot de passe
        // pour insérer une nouvelle entrée dans le keystore de l'instance
        // (la seule méthode concernée est importSecretKey)
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
     * Renvoie un String donnant une description de la clé publique key selon
     * un format dépendant de son algorithme (RSA ou DSA)
     * @param key Une clé publique
     */
    public static String toString(PublicKey key) {
        StringBuilder sb = new StringBuilder();
        // Présente le type de clé
        sb.append("Clé publique de type : ").append(key.getAlgorithm()).append('\n');
        if (key instanceof RSAPublicKey) {
            // Cas d'une clé RSA
            RSAPublicKey rsaPk = (RSAPublicKey)key;
            sb.append("Module de chiffrement :\n");
            sb.append(rsaPk.getModulus()).append('\n');
            sb.append("Exposant public :\n");
            sb.append(rsaPk.getPublicExponent()).append('\n');
        } else if (key instanceof DSAPublicKey) {
            // Cas d'une clé DSA
            DSAPublicKey dsaPk = (DSAPublicKey)key;
            DSAParams dsaParams = dsaPk.getParams();
            sb.append("Paramètres globaux :\n");
            sb.append("P : ").append(dsaParams.getP()).append('\n');
            sb.append("Q : ").append(dsaParams.getQ()).append('\n');
            sb.append("G : ").append(dsaParams.getG()).append('\n');
            sb.append("Clé publique :\n");
            sb.append("Y : ").append(dsaPk.getY());
        } else {
            // Cas non pris en charge
            throw new IllegalArgumentException("Clé de type non traité");
        }
        // Retourne la chaine construite, décrivant la clé
        return sb.toString();
    }

    /**
     * Renvoie un String donnant une description de la clé privée key selon
     * un format dépendant de son algorithme (RSA ou DSA).
     * @param key Une clé privée
     */
    public static String toString(PrivateKey key) {
        StringBuilder sb = new StringBuilder();
        // Présente le type de clé
        sb.append("Clé privée de type : ").append(key.getAlgorithm()).append('\n');
        if (key instanceof RSAPrivateKey) {
            // Cas d'une clé RSA
            RSAPrivateKey rsaPrk = (RSAPrivateKey)key;
            sb.append("Module de chiffrement :\n");
            sb.append(rsaPrk.getModulus()).append('\n');
            sb.append("Exposant privé :\n");
            sb.append(rsaPrk.getPrivateExponent()).append('\n');
        } else if (key instanceof DSAPrivateKey) {
            // Cas d'une clé DSA
            DSAPrivateKey dsaPrk = (DSAPrivateKey)key;
            DSAParams dsaParams = dsaPrk.getParams();
            sb.append("Paramètres globaux :\n");
            sb.append("P : ").append(dsaParams.getP()).append('\n');
            sb.append("Q : ").append(dsaParams.getQ()).append('\n');
            sb.append("G : ").append(dsaParams.getG()).append('\n');
            sb.append("Clé privée :\n");
            sb.append("X : ").append(dsaPrk.getX());
        } else {
            // Cas non pris en charge
            throw new IllegalArgumentException("Clé de type non traité");
        }
        // Retourne la chaine construite, décrivant la clé
        return sb.toString();
    }

    /**
     * Renvoie un String décrivant la liste des descriptions des clés privées
     * contenues dans le keystore de l'instance.
     * @param passwd Le mot de passe des clés privées.
     */
    public String listPrivateKeys(char[] passwd)
            throws GeneralSecurityException {
        StringBuilder sb = new StringBuilder();
        // Récupère tous les alias identifiant les entrées du keystore
        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            // Teste si l'entrée nommée par l'alias courant est une clé privée
            if (ks.entryInstanceOf(alias, KeyStore.PrivateKeyEntry.class)) {
                // Si c'est le cas, présenter l'alias du certificat...
                sb.append("Alias : ").append(alias).append('\n');
                // ...puis la récupérer
                PrivateKey key;
                try {
                    key = (PrivateKey)ks.getKey(alias, passwd);
                    // Décrit la clé privée
                    sb.append(toString(key));
                }
                catch (UnrecoverableKeyException ex) {
                    // Cas où la clé ne peut être récupérée (mot de passe invalide...)
                    sb.append("Clé privée non récupérable : ").append(ex.getLocalizedMessage()).append('\n');
                }
                sb.append('\n');
            }
        }
        // Retourne la chaine construite, décrivant les clés privées du keystore
        return sb.toString();
    }

    /**
     * Insère dans le keystore manipulé une clé secrète key identifié par le nom
     * alias et éventuellement protégé par le mot de passe optionnel passwd.
     * @param key La clé secrète à insérer.
     * @param alias L'alias à associer avec la clé insérée.
     * @param passwd Le mot de passe éventuel pour protéger la clé.
     */
    public void importSecretKey(SecretKey key, String alias, char[] passwd)
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
     * Sauvegarde l'état courant du keystore manipulé dans le fichier file en le
     * protégeant avec le mot de passe passwd.
     * @param file Le fichier dans lequel sauvegarder le keystore de l'instance.
     * @param passwd Le mot de passe protégeant le fichier créé.
     */
    public void save(File file, char[] passwd)
            throws GeneralSecurityException, IOException {
        // Sérialise le contenu du keystore dans le flot attaché au fichier file
        try (OutputStream os = new BufferedOutputStream(new FileOutputStream(file))) {
            ks.store(os, passwd);
        }
    }

    /**
     * Démonstration de la classe.
     * @param args
     */
    /*public static void main(String[] args) {
        try {
            // Nouvelle instance de la classe initialisée avec le fichier store.ks
            KeyStoreTools kst = new KeyStoreTools("JCEKS", "exemple.ks", "mdpKeystore".toCharArray());

            // Liste les certificats et clés privées du keystore
            System.out.println(kst.listCertificates());
            System.out.println(kst.listPrivateKeys("mdpKeystore".toCharArray()));
            System.out.println(kst.listPrivateKeys("mdpKeys".toCharArray()));

            // Obtient une instance d'un générateur de clés secrètes pour l'AES
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            // Spécifie la longueur de la clé (128 bits)
            kg.init(128);
            // Génère la clé
            SecretKey key = kg.generateKey();
            // Insère la clé dans le keystore en lui associant l'alias key6
            kst.importSecretKey(key, "key6", null);

            // Insère le certificat msca.cer en lui associant l'alias key7
            kst.importCertificates(new File("msca.cer"), new String[]{"key7"});

            // Sauvegarde le keystore dans le fichier kstore.ks avec un nouveau mot de passe
            kst.save(new File("kstore.ks"), "x75DT7Rdx98tdZK".toCharArray());

            // Nouvelle instance de la classe initialisée avec le fichier kstore.ks
            kst = new KeyStoreTools("JCEKS", "kstore.ks", "x75DT7Rdx98tdZK".toCharArray());

            // Liste les certificats et clés privées du nouveau keystore
            System.out.println(kst.listCertificates());
            System.out.println(kst.listPrivateKeys("td3exo1".toCharArray()));
        } catch (GeneralSecurityException | IOException ex) {
            Logger.getLogger(KeyStoreTools.class.getName()).log(Level.SEVERE, null, ex);
        }
    }*/
}

