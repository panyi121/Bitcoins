import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Paths;

public class Bitcoin {
	
	public static void main(String[] args) {
		byte[] binaryData = null;
		try {
			binaryData = Files.readAllBytes(Paths.get("src","transactionData-10000-3.bin"));
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		byte[] firstBytes = getBytes(binaryData, 0, 5);
		String word = new String(firstBytes);
		
		System.out.println(word);
	}
	
	private static byte[] getBytes(byte[] src, int start, int end) {
		byte[] bb = new byte[end - start];
		System.arraycopy(src, start, bb, 0, end - start);
		return bb;
	}
}
