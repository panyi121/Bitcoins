
public class NonceTester {
	public static final int DIFFICULTY = 3;

	public static void main(String[] args) {
		// TODO Auto-generated method stub

		
		byte[] header = new byte[82];
		
		long nonce = Long.MIN_VALUE;
		byte[] first24bits = new byte[3];
		
		do {
		//	int time = System.currentTimeMillis();
			byte[] hash = Merkle.dHash(header);
			System.arraycopy(hash, hash.length - DIFFICULTY, first24bits, 0, DIFFICULTY);

		} while (!isAllZeros(first24bits)); /* while the  */
		// we've found a nonce that works so we can add the block header
			
	}
	
	public static boolean isAllZeros(byte[] input) {
		for (int i = 0; i < input.length; i++) {
			if (input[i] != 0x00) {
				return false;
			}
		}
		return true;
	}

}
