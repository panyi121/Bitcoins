import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;


public class Test2 {
	
	public static void main(String[] args) throws IOException {
		// going to test one instance of decrytping a signature field with 
		File outputFile = new File("outputfile.bin");
		System.out.println(outputFile.getCanonicalPath());
		DataOutputStream os = new DataOutputStream(new FileOutputStream("./outputfile.bin"));
		byte[] t = new byte[4];
		t[0] = 0xd;
		
		t[1] = 0xd;
		t[2] = 0xd;
		t[3] = 0xd;
		os.write(t);

	}

}
