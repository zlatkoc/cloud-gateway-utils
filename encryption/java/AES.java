import javax.crypto.*;
import javax.crypto.spec.*;


public class AES {

	private static String asHex (byte buf[]) {
		StringBuffer strbuf = new StringBuffer(buf.length * 2);
		int i;

		for (i = 0; i < buf.length; i++) {
			if (((int) buf[i] & 0xff) < 0x10)
				strbuf.append("0");

			strbuf.append(Long.toString((int) buf[i] & 0xff, 16));
		}

		return strbuf.toString();
	}

	private static byte[] fromHex(String s) {
	    int len = s.length();
	    byte[] data = new byte[len / 2];
	    for (int i = 0; i < len; i += 2) {
	        data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
	                             + Character.digit(s.charAt(i+1), 16));
	    }
	    return data;
	}

	public static String encryptText(String text, String secret_key)
		throws Exception
	{
		// Convert strings to byte arrays
		byte[] input_bytes = text.getBytes();
		byte[] key_bytes = secret_key.getBytes();
		
		// Generate the key for encryption		
		SecretKeySpec secret_key_spec = new SecretKeySpec(key_bytes, "AES");

		// Instantiate the cipher
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, secret_key_spec);		
		
		// Encrypt the input string
		byte[] encrypted_bytes = cipher.doFinal(input_bytes);
				
		// Convert byte arrays to strings
		String encrypted_string = asHex(encrypted_bytes);

		return encrypted_string;
	}

	public static String tryToDecryptText(String text, String secret_key) 
		throws Exception
	{
		// Convert strings to byte arrays
		byte[] encrypted_bytes = fromHex(text);
		byte[] key_bytes = secret_key.getBytes();
		
		// Generate the key for encryption		
		SecretKeySpec secret_key_spec = new SecretKeySpec(key_bytes, "AES");

		// Instantiate the cipher
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, secret_key_spec);
		
		// Decrypt encrypted string
		byte[] decrypted_bytes = cipher.doFinal(encrypted_bytes);
		
		// Convert byte arrays to strings
		String decrypted_string = new String(decrypted_bytes);
		
		return decrypted_string;
	}

	public static void main(String[] args) throws Exception {
		// Set input string and secret key
		String input_string = new String("test šŠčČžŽćĆđĐ добро утро");
		String secret_key = "aaaaaaaaaaaaaaaa";
		
		// Encrypt text
		String encrypted_string = encryptText(
			input_string, secret_key);

		// Try to decrypt text
		String decrypted_string = tryToDecryptText(
			encrypted_string, secret_key);
		
		// Print results
		System.out.println("Secrect key:      " + secret_key);
		System.out.println("Original string:  " + input_string);
		System.out.println("Encrypted string: " + encrypted_string);
		System.out.println("Decrypted string: " + decrypted_string);
		
		if (!input_string.equals(decrypted_string)) {
			System.out.println("Original string and decrypted string differ!!!");
		}
	}
}
