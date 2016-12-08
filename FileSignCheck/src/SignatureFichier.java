import java.security.Signature;
import java.security.SignatureException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.io.FileOutputStream;
import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.FileInputStream;
 
/**
 * Classe permettant de signer un fichier avec une cl� priv�e stock�e dans
 * un fichier. La signature est sauvegard�e dans un fichier.
 * @author Cyril Rabat
 * @version 19/10/2015
 */
public class SignatureFichier {
 
    /**
     * M�thode principale.
     * @param args[0] nom du fichier contenant la cl� priv�e
     * @param args[1] nom du fichier � signer
     * @param args[2] nom du fichier dans lequel sauvegarder la signature
     */
    public static void main(String[] args) {
	// V�rification des arguments
	if(args.length != 3) {
	    System.err.println("Utilisation :");
	    System.err.println("  java SignatureFichier privee fichier signature");
	    System.err.println("    o� :");
	    System.err.println("      - privee    : nom du fichier qui contient la cl� priv�e");
	    System.err.println("      - fichier   : nom du fichier qui doit �tre sign�");
	    System.err.println("      - signature : nom du fichier qui contiendra la signature");
	    System.exit(-1);
	}
 
	// Reconstruction de la cl�
	PrivateKey clePrivee = GestionClesRSA.lectureClePrivee(args[0]);
 
	// Cr�ation de la signature
	Signature signature = null;
	try {
	    signature = Signature.getInstance("SHA1withRSA");
	} catch(NoSuchAlgorithmException e) {
	    System.err.println("Erreur lors de l'initialisation de la signature : " + e);
	    System.exit(-1);
	}
 
	// Initialisation de la signature
	try { 
	    signature.initSign(clePrivee);
	} catch(InvalidKeyException e) {
	    System.err.println("Cl� priv�e invalide : " + e);
	    System.exit(-1);
	}
 
	// Mise-�-jour de la signature par rapport au contenu du fichier
	try {
	    BufferedInputStream fichier = new BufferedInputStream(new FileInputStream(args[1]));
	    byte[] tampon = new byte[1024];
	    int n;
	    while (fichier.available() != 0) {
		n = fichier.read(tampon);
		signature.update(tampon, 0, n);
	    }
	    fichier.close();
	} catch(IOException e) {
	    System.err.println("Erreur lors de la lecture du fichier � signer : " + e);
	    System.exit(-1);
	}
	catch(SignatureException e) {
	    System.err.println("Erreur lors de la mise-�-jour de la signature : " + e);
	    System.exit(-1);
	}
 
	// Sauvegarde de la signature du fichier
	try {
	    FileOutputStream fichier = new FileOutputStream(args[2]);
	    fichier.write(signature.sign());
	    fichier.close();
	} catch(SignatureException e) {
	    System.err.println("Erreur lors de la r�cup�ration de la signature : " + e);
	    System.exit(-1);
	} catch(IOException e) {
	    System.err.println("Erreur lors de la sauvegarde de la signature : " + e);
	    System.exit(-1);
	}
    }
 
}