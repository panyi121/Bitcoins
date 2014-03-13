import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;


public class Merkle {
	public MessageDigest md;
/*
	public static void main(String[] args) throws NoSuchAlgorithmException {
		md = MessageDigest.getInstance("SHA-256");
		String a = "a";
		byte[] a_dHashBytes = dHash(a);
		System.out.println( bitsToHex(a_dHashBytes));
		String five = "five";
		byte[] five_dHashBytes = dHash(five);
		System.out.println( bitsToHex(five_dHashBytes));
		
		byte[] a_five_concat = new byte[a_dHashBytes.length * 2];
		System.arraycopy(a_dHashBytes, 0, a_five_concat, 0, a_dHashBytes.length);
		System.arraycopy(five_dHashBytes, 0, a_five_concat, a_dHashBytes.length, five_dHashBytes.length);
		byte[] concatHash = dHash(a_five_concat);
		System.out.println(bitsToHex(concatHash));
		String[] input = {"a", "five", "word", "input", "example"};
		System.out.println(calcMerkleRoot(input));
	}
	*/
	public Merkle() {
		try {
			md = MessageDigest.getInstance("SHA-256");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public byte[] dHash(byte[] val) {
		md.update(val);
		md.update(md.digest());
		return md.digest();
	}
/*	
	public byte[] dHash(String val) {
		md.update(val.getBytes());
		md.update(md.digest());
		return md.digest();
	}
	public String bitsToHex(byte[] byteArray) {
		StringBuffer result = new StringBuffer();
		for (byte b:byteArray) {
			result.append(String.format("%02x", b));
		}
		return result.toString();
	}
	public String calcMerkleRoot(String[] input) {
		List<byte[]> start = new ArrayList<byte[]>();
		for (int j = 0; j < input.length; j++) {
			start.add(dHash(input[j]));
		}
		while (start.size() != 1) {
			if (start.size() % 2 == 1) {
				start.add(start.get(start.size() - 1));
			}
			List<byte[]> next = new ArrayList<byte[]>();
			for (int i = 0; i < start.size(); i += 2) {
				next.add(dHash(concatHash(start.get(i), start.get(i + 1))));

			}
			start = next;
		}
		return bitsToHex(start.get(0));
	}
	*/
	
	public byte[] calcMerkleRoot(List<byte[]> input) {
		List<byte[]> start = new ArrayList<byte[]>();
		for (int j = 0; j < input.size(); j++) {
			start.add(dHash(input.get(j)));
		}
		while (start.size() != 1) {
			if (start.size() % 2 == 1) {
				start.add(start.get(start.size() - 1));
			}
			List<byte[]> next = new ArrayList<byte[]>();
			for (int i = 0; i < start.size(); i += 2) {
				next.add(dHash(concatHash(start.get(i), start.get(i + 1))));

			}
			start = next;
		}
		return start.get(0);
	}

	// only use this if a and b have the same length
	public byte[] concatHash(byte[] a, byte[] b) {
		if (a.length != b.length) {
			throw new IllegalArgumentException();
		}
		byte[] c = new byte[a.length * 2];
		System.arraycopy(a, 0, c, 0, a.length);
		System.arraycopy(b, 0, c, b.length, a.length);
		return c;
	}
}
