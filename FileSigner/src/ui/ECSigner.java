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
     * Classe permettant la g�n�ration de cl�s pour le DSA sur les courbes elliptiques
     */
    public static class ECKeyPairGenerator {
        // Le g�n�rateur de paire de cl�s
        private final KeyPairGenerator kpg;

        /**
         * Construction d'une instance de la classe
         * @param curveName le nom officiel (NIST) de la courbe utilis�e
         * @throws GeneralSecurityException si la construction du g�n�rateur �choue
         */
        public ECKeyPairGenerator(String curveName) throws GeneralSecurityException {
            this.kpg = KeyPairGenerator.getInstance("ECDSA");
            kpg.initialize(new ECGenParameterSpec(curveName));
        }

        /**
         * G�n�ration de la paire de cl�s pour l'algorithme ECDSA
         * @return
         */
        public KeyPair getECKeyPair() {
            return kpg.generateKeyPair();
        }

        /**
         * M�thode utilitaire listant les courbes impl�ment�es
         * @return une liste des noms officiels des courbes elliptiques impl�ment�es par le Provider
         */
        public static String getCurvesNames() {
            StringBuilder sb = new StringBuilder();
            for(Enumeration<String> curves = ECNamedCurveTable.getNames(); curves.hasMoreElements();){
                sb.append(curves.nextElement()).append('\n');
            }
            return sb.toString();
        }
    }

    // L'objet charg� du calcul de la signature
    private final Signature signer;

    /**
     * Construction d'une instance de la classe
     * @param algorithm l'algorithme impl�ment�
     * @throws GeneralSecurityException si la construction de l'objet signant �choue
     */
    public ECSigner(String algorithm) throws GeneralSecurityException {
        this.signer = Signature.getInstance(algorithm);
    }

    /**
     * Calcul de la signature d'un fichier
     * @param file le fichier � signer
     * @param privateKey la cl� priv�e pour initialiser la signature
     * @return la signature sous forme encod�e en base64
     * @throws GeneralSecurityException si le calcul de la signature �choue
     * @throws IOException si la lecture du fichier �choue
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
            // remise � jour de l'objet signant avec les octets lus
            signer.update(buffer, 0, nl);
        in.close();
        return Base64.encodeBase64String(signer.sign());
    }

    /**
     * Calcul de la signature d'un fichier
     * @param fileName le nom du fichier � signer
     * @param privateKey la cl� priv�e pour initialiser la signature
     * @return la signature sous forme encod�e en base64
     * @throws GeneralSecurityException si le calcul de la signature �choue
     * @throws IOException si la lecture du fichier �choue
     */
    public String signFile(String fileName, PrivateKey privateKey)
            throws GeneralSecurityException, IOException {
        return signFile(new File(fileName), privateKey);
    }

    /**
     * V�rification de la signature d'un fichier
     * @param file file le fichier � v�rifier
     * @param publicKey la cl� publique initialisant la v�rification
     * @param tagB64 l'encodage en Base64 de la signature � v�rifier
     * @return <code>true</code> si la signature est correcte et <code>false</code> sinon
     * @throws GeneralSecurityException  si la v�rification de la signature �choue
     * @throws IOException si la lecture du fichier �choue
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
        // boucle de lecture pour la v�rification de la signature
        while((nl = in.read(buffer)) != -1)
            // remise � jour de l'objet signant avec les octets lus
            signer.update(buffer, 0, nl);
        in.close();
        return signer.verify(Base64.decodeBase64(tagB64));
    }

    /**
     * V�rification de la signature d'un fichier
     * @param fileName file le nom du fichier � v�rifier
     * @param publicKey la cl� publique initialisant la v�rification
     * @param tagB64 l'encodage en Base64 de la signature � v�rifier
     * @return <code>true</code> si la signature est correcte et <code>false</code> sinon
     * @throws GeneralSecurityException  si la v�rification de la signature �choue
     * @throws IOException si la lecture du fichier �choue
     */
    public boolean verifyFile(String fileName, PublicKey publicKey, String tagB64)
            throws GeneralSecurityException, IOException {
        return verifyFile(new File(fileName), publicKey, tagB64);
    }
}
