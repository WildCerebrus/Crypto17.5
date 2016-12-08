import java.security.Signature;
import java.security.SignatureException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.io.FileInputStream;
import java.io.BufferedInputStream;
import java.io.IOException;
 
/**
 * Classe permettant de v�rifier la signature d'un fichier � partir de la
 * cl� publique.
 * @author Cyril Rabat
 * @version 19/10/2015
 */
public class VerificationSignature {
 
    /**
     * M�thode principale.
     * @param args[0] nom du fichier dont on veut v�rifier la signature
     * @param args[1] nom du fichier contenant la signature
     * @param args[2] nom du fichier contenant la cl� publique
     */
    public static void main(String[] args) {
	// V�rification des arguments
	if(args.length != 3) {
	    System.err.println("Utilisation :");
	    System.err.println("  java VerificationSignature fichier signature publique");
	    System.err.println("    o� :");
	    System.err.println("      - fichier   : nom du fichier dont on v�rifie la signature");
	    System.err.println("      - signature : nom du fichier qui contient la signature");
	    System.err.println("      - publique  : nom du fichier qui contient la cl� publique");
	    System.exit(-1);
	}
 
	// Reconstruction de la cl�
	PublicKey clePublique = GestionClesRSA.lectureClePublique(args[2]);
 
	// Lecture de la signature
	byte[] signatureFournie = null;
	try {
	    FileInputStream fichier = new FileInputStream(args[1]);
	    signatureFournie = new byte[fichier.available()]; 
	    fichier.read(signatureFournie);
	    fichier.close();
	} catch(IOException e) {
	    System.err.println("Erreur lors de la lecture de la signature : " + e);
	    System.exit(-1);
	}
 
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
	    signature.initVerify(clePublique);
	} catch(InvalidKeyException e) {
	    System.err.println("Cle publique invalide : " + e);
	    System.exit(-1);
	}
 
	// Mise-�-jour de la signature par rapport au contenu du fichier
	try {
	    BufferedInputStream fichier = new BufferedInputStream(new FileInputStream(args[0]));
	    byte[] tampon = new byte[1024];
	    int n;
	    while (fichier.available() != 0) {
		n = fichier.read(tampon);
		signature.update(tampon, 0, n);
	    }
	    fichier.close();
	} catch(IOException e) {
	    System.err.println("Erreur lors de la lecture du fichier � v�rifier : " + e);
	    System.exit(-1);
	}
	catch(SignatureException e) {
	    System.err.println("Erreur lors de la mise-�-jour de la signature : " + e);
	    System.exit(-1);
	}
 
	// Comparaison des deux signatures
	try {
	    if(signature.verify(signatureFournie))
		System.out.println("Fichier OK");
	    else
		System.out.println("Fichier invalide");
	} catch(SignatureException e) {
	    System.err.println("Erreur lors de la v�rification des signatures : " + e);
	    System.exit(-1);
	}
    }
 
}
