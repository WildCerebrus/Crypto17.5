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
 * Classe pr�sentant des m�thodes permettant la manipulation ais�e des keystores.
 * @author Julien Lepagnot
 * @modifiers Maximilien Therras, Nathan LeDigabel, Mathieu Althuser
 */
public class KeyStoreTools {

    // Le keystore de l'instance
    private KeyStore ks;

    // Le mot de passe du keystore
    private char[] storepass;

    // Associations des OID pouvant appara�tre dans un nom distingu�
    // � compl�ter avec les OID de pr�fixe 1.2.840.113549.1.9
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
     * Acc�s au nom X500 du sujet du certificat.
     * @param cert Un certificat X.509
     * @return Le nom au format RFC2253 + traduction des OID du sujet du certificat
     */
    private static String getSubjectName(X509Certificate cert) {
        X500Principal subject = cert.getSubjectX500Principal();
        return subject.getName(X500Principal.RFC2253, OID_MAP);
    }

    /**
     * Acc�s au nom X500 de l'autorit� ayant d�livr� le certificat.
     * @param cert Un certificat X.509
     * @return Le nom au format RFC2253 + traduction des OID de l'autorit� ayant d�livr� le certificat
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
        // Pr�sente le sujet du certificat
        sb.append("D�tenteur : ").append(getSubjectName(cert)).append('\n');
        // Pr�sente l'�metteur du certificat
        sb.append("Autorit� de certification : ").append(getIssuerName(cert)).append('\n');
        // Pr�sente la date de d�but de validit�
        sb.append("Valable du ").append(cert.getNotBefore()).append('\n');
        // Pr�sente la date de fin de validit�
        sb.append("Valable jusqu'au ").append(cert.getNotAfter()).append('\n');
        // D�crit la cl� publique contenue dans le certificat
        sb.append(toString(cert.getPublicKey()));
        // Retourne la chaine construite, d�crivant le certificat
        return sb.toString();
    }

    /**
     * Renvoie un String d�crivant la liste des descriptions des certificats
     * contenus dans le keystore de l'instance.
     */
    public String listCertificates()
            throws GeneralSecurityException {
        StringBuilder sb = new StringBuilder();
        // R�cup�re tous les alias identifiant les entr�es du keystore
        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            // Teste si l'entr�e nomm�e par l'alias courant est un certificat
            if (ks.isCertificateEntry(alias)) {
                // Si c'est le cas la r�cup�rer
                Certificate cert = ks.getCertificate(alias);
                // Pr�sente l'alias du certificat
                sb.append("Alias : ").append(alias).append('\n');
                if (cert instanceof X509Certificate) {
                    // Cas d'un certificat X.509
                    sb.append(toString((X509Certificate)cert));
                }
                else {
                    // Cas non pris en charge
                    sb.append("Certificat de type non trait�\n");
                }
                sb.append('\n');
            }
        }
        // Retourne la chaine construite, d�crivant les certificats du keystore
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
     * Importe dans le keystore le certificat cert sous le nom alias.
     * @param cert Le certificat � ins�rer.
     * @param alias L'alias � associer avec le certificat ins�r�.
     */
    public void importCertificate(Certificate cert, String alias)
            throws GeneralSecurityException {
        // Ins�re le certificat dans le keystore
        ks.setCertificateEntry(alias, cert);
    }

    /**
     * Importe dans le keystore les certificats contenu dans le fichier de chemin
     * file, le i-i�me certificat �tant identifi� par aliases[i-1].
     * @param file Le fichier contenant les certificats � ins�rer.
     * @param aliases Les alias � associer avec les certificats ins�r�s.
     */
    public void importCertificates(File file, String[] aliases)
            throws GeneralSecurityException, IOException {
        // Le flot transmis � la m�thode generateCertificate doit supporter
        // les op�rations mark et reset ce qui est le cas de BufferedInputStream
        // mais pas celui de FileInputStream
        InputStream in = new BufferedInputStream(new FileInputStream(file));
        // L'usine est sp�cialis�e dans le traitement des certificats X509.
        CertificateFactory factory = CertificateFactory.getInstance("X509");
        // Comme les lectures ne sont pas faites explicitement, c'est la m�thode
        // InputStream.available qui permet de savoir si la fin de fichier est atteinte
        for (int i = 0; in.available() > 0; i++) {
            importCertificate(factory.generateCertificate(in), aliases[i]);
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
