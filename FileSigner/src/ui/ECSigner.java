package ui;
import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.Enumeration;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Une classe permettant designer des documents avec le DSA sur les courbes elliptiques
 * @author Patrick Guichet
 */
public class ECSigner {
    // Installation du provider BouncyCastle
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Classe permettant la génération de clés pour le DSA sur les courbes elliptiques
     */
    public static class ECKeyPairGenerator {
        // Le générateur de paire de clés
        private final KeyPairGenerator kpg;

        /**
         * Construction d'une instance de la classe
         * @param curveName le nom officiel (NIST) de la courbe utilisée
         * @throws GeneralSecurityException si la construction du générateur échoue
         */
        public ECKeyPairGenerator(String curveName) throws GeneralSecurityException {
            this.kpg = KeyPairGenerator.getInstance("ECDSA");
            kpg.initialize(new ECGenParameterSpec(curveName));
        }

        /**
         * Génération de la paire de clés pour l'algorithme ECDSA
         * @return
         */
        public KeyPair getECKeyPair() {
            return kpg.generateKeyPair();
        }

        /**
         * Méthode utilitaire listant les courbes implémentées
         * @return une liste des noms officiels des courbes elliptiques implémentées par le Provider
         */
        public static String getCurvesNames() {
            StringBuilder sb = new StringBuilder();
            for(Enumeration<String> curves = ECNamedCurveTable.getNames(); curves.hasMoreElements();){
                sb.append(curves.nextElement()).append('\n');
            }
            return sb.toString();
        }
    }

    // L'objet chargé du calcul de la signature
    private final Signature signer;

    /**
     * Construction d'une instance de la classe
     * @param algorithm l'algorithme implémenté
     * @throws GeneralSecurityException si la construction de l'objet signant échoue
     */
    public ECSigner(String algorithm) throws GeneralSecurityException {
        this.signer = Signature.getInstance(algorithm);
    }

    /**
     * Calcul de la signature d'un fichier
     * @param file le fichier à signer
     * @param privateKey la clé privée pour initialiser la signature
     * @return la signature sous forme encodée en base64
     * @throws GeneralSecurityException si le calcul de la signature échoue
     * @throws IOException si la lecture du fichier échoue
     */
    public String signFile(File file, PrivateKey privateKey)
            throws GeneralSecurityException, IOException {
        signer.initSign(privateKey);
        // le flot entrant
        InputStream in = new BufferedInputStream(new FileInputStream(file));
        // le buffer de lecture
        byte[] buffer = new byte[1024];
        // le nombre d'octets lus
        int nl;
        // boucle de lecture pour le calcul de la signature
        while((nl = in.read(buffer)) != -1)
            // remise à jour de l'objet signant avec les octets lus
            signer.update(buffer, 0, nl);
        in.close();
        return Base64.encodeBase64String(signer.sign());
    }

    /**
     * Calcul de la signature d'un fichier
     * @param fileName le nom du fichier à signer
     * @param privateKey la clé privée pour initialiser la signature
     * @return la signature sous forme encodée en base64
     * @throws GeneralSecurityException si le calcul de la signature échoue
     * @throws IOException si la lecture du fichier échoue
     */
    public String signFile(String fileName, PrivateKey privateKey)
            throws GeneralSecurityException, IOException {
        return signFile(new File(fileName), privateKey);
    }

    /**
     * Vérification de la signature d'un fichier
     * @param file file le fichier à vérifier
     * @param publicKey la clé publique initialisant la vérification
     * @param tagB64 l'encodage en Base64 de la signature à vérifier
     * @return <code>true</code> si la signature est correcte et <code>false</code> sinon
     * @throws GeneralSecurityException  si la vérification de la signature échoue
     * @throws IOException si la lecture du fichier échoue
     */
    public boolean verifyFile(File file, PublicKey publicKey, String tagB64)
            throws GeneralSecurityException, IOException {
        signer.initVerify(publicKey);
        // le flot entrant
        InputStream in = new BufferedInputStream(new FileInputStream(file));
        // le buffer de lecture
        byte[] buffer = new byte[1024];
        // le nombre d'octets lus
        int nl;
        // boucle de lecture pour la vérification de la signature
        while((nl = in.read(buffer)) != -1)
            // remise à jour de l'objet signant avec les octets lus
            signer.update(buffer, 0, nl);
        in.close();
        return signer.verify(Base64.decodeBase64(tagB64));
    }

    /**
     * Vérification de la signature d'un fichier
     * @param fileName file le nom du fichier à vérifier
     * @param publicKey la clé publique initialisant la vérification
     * @param tagB64 l'encodage en Base64 de la signature à vérifier
     * @return <code>true</code> si la signature est correcte et <code>false</code> sinon
     * @throws GeneralSecurityException  si la vérification de la signature échoue
     * @throws IOException si la lecture du fichier échoue
     */
    public boolean verifyFile(String fileName, PublicKey publicKey, String tagB64)
            throws GeneralSecurityException, IOException {
        return verifyFile(new File(fileName), publicKey, tagB64);
    }
}
