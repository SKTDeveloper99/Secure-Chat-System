package main;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Main {

	private static final String  PUBLIC_KEY_FILE = "Public.key";
	private static final String  PRIVATE_KEY_FILE = "Private.key";		

	public static void main(String[] args) throws IOException {
	try {
		System.out.println("\n-----  AES SYSTEM BEGINS -------\n");
		Sender aes = new Sender("What is going on");
		String encdata = aes.encrypt("tachanka");
		System.out.println("Encrypted data - " + encdata );
		String decdata = aes.dencrypt(encdata);
		System.out.println("Decrypted data - " + decdata);
		System.out.println("\n-----  AES SYSTEM COMPLETES -------\n");
	} catch (Exception e) {
		e.printStackTrace();
	}
	
		try {
			System.out.println("\n----- GENERATE PUBLIC AND PRIVATE KEY -------\n");
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			PublicKey publicKey = keyPair.getPublic();
			PrivateKey privateKey = keyPair.getPrivate();
			System.out.println("\n----- PULLING OUT PARAMETERS WHICH MAKES KEYPAIR -------\n");
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			RSAPublicKeySpec rsaPubKeySpec = keyFactory.getKeySpec(publicKey, RSAPublicKeySpec.class);
			RSAPrivateKeySpec rsaPrivKeySpec = keyFactory.getKeySpec(privateKey, RSAPrivateKeySpec.class);

			System.out.println("\n----- SAVING PUBLIC KEY AND PRIVATE KEY TO FILES -------\n");

			Main rsaObj = new Main();

			rsaObj.saveKeys(PUBLIC_KEY_FILE, rsaPubKeySpec.getModulus(),rsaPubKeySpec.getPublicExponent());
			rsaObj.saveKeys(PRIVATE_KEY_FILE, rsaPrivKeySpec.getModulus(),rsaPrivKeySpec.getPrivateExponent());

			//Encrypt Data using Public Key
			byte[] encryptedData = rsaObj.encryptedData("Veni vidi vici");
			
			//Decrypt Data using Private Key
			rsaObj.decryptData(encryptedData);
			
		} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
			System.out.println(e);
		}
	}

	private byte[] encryptedData(String data) throws IOException {
		System.out.println("\n----- ENCRYPTION STARTED -------\n");
		System.out.println("Data Before Encryption: " + data);
		byte[] dataToEncrypt = data.getBytes();
		byte[] encryptedData = null;
		try {
			PublicKey pubKey = readPublicKeyFromFile(this.PUBLIC_KEY_FILE);
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, pubKey);
			encryptedData = cipher.doFinal(dataToEncrypt);
			
			System.out.println("Encrypted data: " + new String (encryptedData));
			
		} catch (IOException |  NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
		}
		System.out.println("\n----- ENCRYPTION COMPLETED  -------\n");
		return encryptedData;
	}
	
	private void decryptData(byte[] data) throws IOException {
		System.out.println("\n----- DECRYPTION STARTED -------\n");
		byte[] decryptedData = null;
		try {
			PrivateKey privateKey = readPrivateKeyFromFile(this.PRIVATE_KEY_FILE);
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			decryptedData = cipher.doFinal(data);
			System.out.println("Decrypted data: " + new String(decryptedData));
		} catch (IOException |  NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
		}
		System.out.println("\n----- DECRYPTION COMPLETED  -------\n");
	}


	public PublicKey readPublicKeyFromFile(String fileName) throws IOException {
		FileInputStream fis = null;
		ObjectInputStream ois = null;
		try {
			fis = new FileInputStream(new File(fileName));
			ois = new ObjectInputStream(fis);
			BigInteger modulus = (BigInteger) ois.readObject();
			BigInteger exponent = (BigInteger) ois.readObject();
			// Get Public Key
			RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(modulus, exponent);
			KeyFactory fact = KeyFactory.getInstance("RSA");
			PublicKey publicKey = fact.generatePublic(rsaPublicKeySpec);
			return publicKey;
		} catch (IOException | ClassNotFoundException | NoSuchAlgorithmException | InvalidKeySpecException e) {
			e.printStackTrace();
		} finally {
			if (ois != null) {
				ois.close();
				if (fis != null) {
					fis.close();
				}
			}
		}
		return null;
	}
	
	public PrivateKey readPrivateKeyFromFile(String fileName) throws IOException {
		FileInputStream fis = null;
		ObjectInputStream ois = null;
		try {
			fis = new FileInputStream(new File(fileName));
			ois = new ObjectInputStream(fis);
			BigInteger modulus = (BigInteger) ois.readObject();
			BigInteger exponent = (BigInteger) ois.readObject();
			// Get Private Key
			RSAPrivateKeySpec rsaPrivateKeySpec = new RSAPrivateKeySpec(modulus, exponent);
			KeyFactory fact = KeyFactory.getInstance("RSA");
			PrivateKey privateKey = fact.generatePrivate(rsaPrivateKeySpec);
			return privateKey;
		} catch (IOException | ClassNotFoundException | NoSuchAlgorithmException | InvalidKeySpecException e) {
			e.printStackTrace();
		} finally {
			if (ois != null) {
				ois.close();
				if (fis != null) {
					fis.close();
				}
			}
		}
		return null;
	}

	private void saveKeys(String fileName, BigInteger mod, BigInteger exp) throws IOException {
		FileOutputStream fos = null;
		ObjectOutputStream oos = null;

		try {
			System.out.println("Generating " + fileName + " ...");
			fos = new FileOutputStream(fileName);
			oos = new ObjectOutputStream(new BufferedOutputStream(fos));
			oos.writeObject(mod);
			oos.writeObject(exp);
			System.out.println(fileName + "generated successfully");
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			if (oos != null) {
				oos.close();
				if (fos != null) {
					fos.close();
				}
			}
		}

	}

}
