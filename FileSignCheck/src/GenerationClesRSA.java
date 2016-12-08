import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 * Classe permettant de g�n�rer une paire de cl�s priv�e/publique et de les
 * sauvegarder dans des fichiers.
 */
public class GenerationClesRSA {

    /**
     * M�thode principale.
     * @param args[0] nom du fichier dans lequel sauvegarder la cl� priv�e
     * @param args[1] nom du fichier dans lequel sauvegarder la cl� publique
     */
    public static void main(String[] args) {
	// Cr�ation d'un g�n�rateur RSA
	KeyPairGenerator generateurCles = null;
	try {
	    generateurCles = KeyPairGenerator.getInstance("RSA");
	    generateurCles.initialize(2048);
	} catch(NoSuchAlgorithmException e) {
	    System.err.println("Erreur lors de l'initialisation du g�n�rateur de cl�s : " + e);
	    System.exit(-1);
	}

	// G�n�ration de la paire de cl�s
	KeyPair paireCles = generateurCles.generateKeyPair();

	// Sauvegarde de la cl� priv�e
	GestionClesRSA.sauvegardeClePrivee(paireCles.getPrivate(), args[0]);

	// Sauvegarde de la cl� publique
	GestionClesRSA.sauvegardeClePublique(paireCles.getPublic(), args[1]);

	System.out.println("Cl�s sauvegard�es.");
    }

}