package main;

import java.security.Key;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class Receiver {
	
	private static final String  PUBLIC_KEY_FILE = "ReceiverPublic.key";
	private static final String  PRIVATE_KEY_FILE = "ReceiverPrivate.key";	
	private static final String ALGO = "AES";
	private byte[] keyValue;
	
	public Receiver(String key) {
		keyValue = key.getBytes();
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
