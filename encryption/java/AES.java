import javax.crypto.*;
import javax.crypto.spec.*;


public class AES {

	/**
	 * Turns array of bytes into string
	 *
	 * @param buf	Array of bytes to convert to hex string
	 * @return	Generated hex string
	 */
	public static String asHex (byte buf[]) {
		StringBuffer strbuf = new StringBuffer(buf.length * 2);
		int i;

		for (i = 0; i < buf.length; i++) {
			if (((int) buf[i] & 0xff) < 0x10)
				strbuf.append("0");

			strbuf.append(Long.toString((int) buf[i] & 0xff, 16));
		}

		return strbuf.toString();
	}

	public static void main(String[] args) throws Exception {
		// Set input string and secret key
		String input_string = new String("test šŠčČžŽćĆđĐ");
		String key_string = "aaaaaaaaaaaaaaaa";
		
		// Convert strings to byte arrays
		byte[] input_bytes = input_string.getBytes();
		byte[] key_bytes = key_string.getBytes();
		
		// Generate the key for encryption		
		SecretKeySpec secret_key = new SecretKeySpec(key_bytes, "AES");

		// Instantiate the cipher
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, secret_key);		
		
		// Encrypt the input string
		byte[] encrypted_bytes = cipher.doFinal(input_bytes);
		
		// Initialize the same cipher for decryption
		cipher.init(Cipher.DECRYPT_MODE, secret_key);
		
		// Decrypt encrypted string
		byte[] decrypted_bytes = cipher.doFinal(encrypted_bytes);
		
		// Convert byte arrays to strings
		String encrypted_string = asHex(encrypted_bytes);
		String decrypted_string = new String(decrypted_bytes);
		
		// Print results
		System.out.println("Original string: " + input_string);
		System.out.println("Encrypted string: " + encrypted_string);
		System.out.println("Decrypted string: " + decrypted_string);
		
		if (!input_string.equals(decrypted_string)) {
			throw new Exception("Original string and decrypted string differ.");
		}
		
	}
}
