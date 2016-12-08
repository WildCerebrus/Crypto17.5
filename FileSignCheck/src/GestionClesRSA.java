import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import java.io.IOException;
import java.io.FileInputStream;
import java.io.ObjectInputStream;
import java.io.BufferedInputStream;
import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.io.BufferedOutputStream;
import java.math.BigInteger;

/**
 * Classe permettant de sauvegarder et charger des cl�s priv�es ou publiques
 * depuis des fichiers.
 */
public class GestionClesRSA {

	private KeyStore ks;
	private char[] passwd;
    /**
     * Sauvegarde de la cl� publique dans un fichier.
     * @param clePublique la cl� publique
     * @param nomFichier le nom du fichier dans lequel sauvegarder la cl�
     */
    public static void sauvegardeClePublique(PublicKey clePublique, String nomFichier) {
		RSAPublicKeySpec specification = null;
		try {
		    KeyFactory usine = KeyFactory.getInstance("RSA");
		    specification = usine.getKeySpec(clePublique, RSAPublicKeySpec.class);
		} catch(NoSuchAlgorithmException e) {
		    System.err.println("RSA inconnu : " + e);
		    System.exit(-1);
		} catch(InvalidKeySpecException e) {
		    System.err.println("Cle incorrecte : " + e);
		    System.exit(-1);  
		}
	
		try {
		    ObjectOutputStream fichier = new ObjectOutputStream(new BufferedOutputStream(new FileOutputStream(nomFichier)));
		    fichier.writeObject(specification.getModulus());
		    fichier.writeObject(specification.getPublicExponent());
		    fichier.close();	
		} catch(IOException e) {
		    System.err.println("Erreur lors de la sauvegarde de la cl� : " + e);
		    System.exit(-1);
		}
    }

    /**
     * Sauvegarde de la cl� priv�e dans un fichier.
     * @param clePublique la cl� priv�e
     * @param nomFichier le nom du fichier dans lequel sauvegarder la cl�
     */
    public static void sauvegardeClePrivee(PrivateKey clePrivee, String nomFichier) {
		RSAPrivateKeySpec specification = null;
		try {
		    KeyFactory usine = KeyFactory.getInstance("RSA");
		    specification = usine.getKeySpec(clePrivee, RSAPrivateKeySpec.class);
		} catch(NoSuchAlgorithmException e) {
		    System.err.println("Algorithme RSA inconnu : " + e);
		    System.exit(-1);
		} catch(InvalidKeySpecException e) {
		    System.err.println("Cl� incorrecte : " + e);
		    System.exit(-1);  
		}
	
		try {
		    ObjectOutputStream fichier = new ObjectOutputStream(new BufferedOutputStream(new FileOutputStream(nomFichier)));
		    fichier.writeObject(specification.getModulus());
		    fichier.writeObject(specification.getPrivateExponent());
		    fichier.close();	
		} catch(IOException e) {
		    System.err.println("Erreur lors de la sauvegarde de la cl� : " + e);
		    System.exit(-1);
		}
    }

    /**
     * Lecture d'une cl� priv�e depuis un fichier.
     * @param nomFichier le nom du fichier contenant la cl� priv�e
     * @return la cl� priv�e
     */
    public static PrivateKey lectureClePrivee(String nomFichier) {
		BigInteger modulo = null, exposant = null;
		try {
		    ObjectInputStream ois = new ObjectInputStream(new BufferedInputStream(new FileInputStream(nomFichier)));	    
		    modulo = (BigInteger) ois.readObject();
		    exposant = (BigInteger) ois.readObject();
		} catch(IOException e) {
		    System.err.println("Erreur lors de la lecture de la cl� : " + e);
		    System.exit(-1);
		} catch(ClassNotFoundException e) {
		    System.err.println("Fichier de cle incorrect : " + e);
		    System.exit(-1);
		}
	
		PrivateKey clePrivee = null;
		try {
		    RSAPrivateKeySpec specification = new RSAPrivateKeySpec(modulo, exposant);
		    KeyFactory usine = KeyFactory.getInstance("RSA");
		    clePrivee = usine.generatePrivate(specification);
		} catch(NoSuchAlgorithmException e) {
		    System.err.println("Algorithme RSA inconnu : " + e);
		    System.exit(-1);
		} catch(InvalidKeySpecException e) {
		    System.err.println("Sp�cification incorrecte : " + e);
		    System.exit(-1);
		}
		return clePrivee;
    }

    /**
     * Lecture d'une cl� publique depuis un fichier.
     * @param nomFichier le nom du fichier contenant la cl� publique
     * @return la cl� publique
     */
    public static PublicKey lectureClePublique(String nomFichier) {
		BigInteger modulo = null, exposant = null;
		try {
		    ObjectInputStream ois = new ObjectInputStream(new BufferedInputStream(new FileInputStream(nomFichier)));	    
		    modulo = (BigInteger) ois.readObject();
		    exposant = (BigInteger) ois.readObject();
		} catch(IOException e) {
		    System.err.println("Erreur lors de la lecture de la cl� : " + e);
		    System.exit(-1);
		} catch(ClassNotFoundException e) {
		    System.err.println("Fichier de cl� incorrect : " + e);
		    System.exit(-1);
		}
	
		PublicKey clePublique = null;
		try {
		    RSAPublicKeySpec specification = new RSAPublicKeySpec(modulo, exposant);
		    KeyFactory usine = KeyFactory.getInstance("RSA");
		    clePublique = usine.generatePublic(specification);
		} catch(NoSuchAlgorithmException e) {
		    System.err.println("Algorithme RSA inconnu : " + e);
		    System.exit(-1);
		} catch(InvalidKeySpecException e) {
		    System.err.println("Sp�cification incorrecte : " + e);
		    System.exit(-1);
		}
		return clePublique;
    }

}