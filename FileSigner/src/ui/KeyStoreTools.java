package ui;
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

import javax.crypto.SecretKey;
import javax.security.auth.x500.X500Principal;

/**
 * Classe présentant des méthodes permettant la manipulation aisée des keystores.
 * @author Julien Lepagnot
 * @modifiers Maximilien Therras, Nathan LeDigabel, Mathieu Althuser
 */
public class KeyStoreTools {

    // Le keystore de l'instance
    private KeyStore ks;

    // Le mot de passe du keystore
    private char[] storepass;

    // Associations des OID pouvant apparaître dans un nom distingué
    // à compléter avec les OID de préfixe 1.2.840.113549.1.9
    private static final Map<String, String> OID_MAP = new HashMap<>();
    static {
        OID_MAP.put("1.2.840.113549.1.9.1", "emailAddress");
        OID_MAP.put("1.2.840.113549.1.9.2", "unstructuredName");
        OID_MAP.put("1.2.840.113549.1.9.8", "unstructuredAddress");
        OID_MAP.put("1.2.840.113549.1.9.16", "S/MIME Object Identifier Registry");
    }

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
     * Accès au nom X500 du sujet du certificat.
     * @param cert Un certificat X.509
     * @return Le nom au format RFC2253 + traduction des OID du sujet du certificat
     */
    private static String getSubjectName(X509Certificate cert) {
        X500Principal subject = cert.getSubjectX500Principal();
        return subject.getName(X500Principal.RFC2253, OID_MAP);
    }

    /**
     * Accès au nom X500 de l'autorité ayant délivré le certificat.
     * @param cert Un certificat X.509
     * @return Le nom au format RFC2253 + traduction des OID de l'autorité ayant délivré le certificat
     */
    private static String getIssuerName(X509Certificate cert) {
        X500Principal issuer = cert.getIssuerX500Principal();
        return issuer.getName(X500Principal.RFC2253, OID_MAP);
    }

    /**
     * Renvoie un String donnant une description d'un certificat X.509.
     * @param cert Un certificat X.509
     */
    public static String toString(X509Certificate cert) {
        StringBuilder sb = new StringBuilder();
        // Présente le sujet du certificat
        sb.append("Détenteur : ").append(getSubjectName(cert)).append('\n');
        // Présente l'émetteur du certificat
        sb.append("Autorité de certification : ").append(getIssuerName(cert)).append('\n');
        // Présente la date de début de validité
        sb.append("Valable du ").append(cert.getNotBefore()).append('\n');
        // Présente la date de fin de validité
        sb.append("Valable jusqu'au ").append(cert.getNotAfter()).append('\n');
        // Décrit la clé publique contenue dans le certificat
        sb.append(toString(cert.getPublicKey()));
        // Retourne la chaine construite, décrivant le certificat
        return sb.toString();
    }

    /**
     * Renvoie un String décrivant la liste des descriptions des certificats
     * contenus dans le keystore de l'instance.
     */
    public String listCertificates()
            throws GeneralSecurityException {
        StringBuilder sb = new StringBuilder();
        // Récupère tous les alias identifiant les entrées du keystore
        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            // Teste si l'entrée nommée par l'alias courant est un certificat
            if (ks.isCertificateEntry(alias)) {
                // Si c'est le cas la récupérer
                Certificate cert = ks.getCertificate(alias);
                // Présente l'alias du certificat
                sb.append("Alias : ").append(alias).append('\n');
                if (cert instanceof X509Certificate) {
                    // Cas d'un certificat X.509
                    sb.append(toString((X509Certificate)cert));
                }
                else {
                    // Cas non pris en charge
                    sb.append("Certificat de type non traité\n");
                }
                sb.append('\n');
            }
        }
        // Retourne la chaine construite, décrivant les certificats du keystore
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
     * Importe dans le keystore le certificat cert sous le nom alias.
     * @param cert Le certificat à insérer.
     * @param alias L'alias à associer avec le certificat inséré.
     */
    public void importCertificate(Certificate cert, String alias)
            throws GeneralSecurityException {
        // Insère le certificat dans le keystore
        ks.setCertificateEntry(alias, cert);
    }

    /**
     * Importe dans le keystore les certificats contenu dans le fichier de chemin
     * file, le i-ième certificat étant identifié par aliases[i-1].
     * @param file Le fichier contenant les certificats à insérer.
     * @param aliases Les alias à associer avec les certificats insérés.
     */
    public void importCertificates(File file, String[] aliases)
            throws GeneralSecurityException, IOException {
        // Le flot transmis à la méthode generateCertificate doit supporter
        // les opérations mark et reset ce qui est le cas de BufferedInputStream
        // mais pas celui de FileInputStream
        InputStream in = new BufferedInputStream(new FileInputStream(file));
        // L'usine est spécialisée dans le traitement des certificats X509.
        CertificateFactory factory = CertificateFactory.getInstance("X509");
        // Comme les lectures ne sont pas faites explicitement, c'est la méthode
        // InputStream.available qui permet de savoir si la fin de fichier est atteinte
        for (int i = 0; in.available() > 0; i++) {
            importCertificate(factory.generateCertificate(in), aliases[i]);
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
