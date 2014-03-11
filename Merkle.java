import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;


public class Merkle {
	
	public static void main(String[] args) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		String a = "a";
		md.update(a.getBytes());
		byte[] byteArray = md.digest();
		md.update(byteArray);
		byteArray = md.digest();
		StringBuffer result = new StringBuffer();
		for (byte b:byteArray) {
		    result.append(String.format("%02x", b));
		}
		System.out.println(result.toString());
	}

	
}
