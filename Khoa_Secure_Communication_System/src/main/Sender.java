package main;

import java.security.Key;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class Sender {

	private static final String  PUBLIC_KEY_FILE = "SenderPublic.key";
	private static final String  PRIVATE_KEY_FILE = "SenderPrivate.key";		

	private static final String ALGO = "AES";
	private byte[] keyValue;
	
	public Sender(String key) {
		keyValue = key.getBytes();
	}
	
	public String encrypt(String data) throws Exception {
		Key key = generateKey();
		Cipher c = Cipher.getInstance(ALGO);
		c.init(Cipher.ENCRYPT_MODE, key);
		byte[] encVal = c.doFinal(data.getBytes());
		String encryptedValue = java.util.Base64.getEncoder().encodeToString(encVal);
		return encryptedValue;
	}
	
	public String dencrypt(String encryptedData) throws Exception {
		Key key = generateKey();
		Cipher c = Cipher.getInstance(ALGO);
		c.init(Cipher.DECRYPT_MODE, key);
		byte[] decodedValue = java.util.Base64.getDecoder().decode(encryptedData);
		byte[] decValue = c.doFinal(decodedValue);
		String decryptedValue = new String(decValue);
		return decryptedValue;
	}

	private Key generateKey() throws Exception {
		Key key = new SecretKeySpec(keyValue, ALGO);
		return key;
	}
}
