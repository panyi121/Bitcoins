import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.crypto.encodings.PKCS1Encoding;


public class Test {

	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		// TODO Auto-generated method stub
		/*
		String pubkey = "-----BEGIN RSA PUBLIC KEY-----\nMIGJAoGBAN3MxXHcbc1VNKTOgdm7W+i/dVnjv8vYGlbkdaTKzYgi8rQm126Sri87\n702UBNzmkkZyKbRKL/Bfc4EG8/Mt9Pd2xQlRyXCL9FnIFWHyhfIQtW+oBsGI5UhG\nI8B8MiPOMfb6d/PdK+vd4riUxHAvCkHW5Lw0szAD1RVGbkG/7qnzAgMBAAE=\n-----END RSA PUBLIC KEY-----";

		Merkle m = new Merkle();
		byte[] hash = m.dHash(pubkey.getBytes());
		System.out.println(bitsToHex(hash));

		// RSA testing
		String publicKey = "-----BEGIN RSA PUBLIC KEY-----\n" + 
				"MIGJAoGBANu2X9ijlIhDbaua5+x9BK/vrbntU6HQc1lO1RRCpRfK9DWhkzzJwIAB\n" +
				"Bm1NEWpTN4DhSv04qcbMpSzqSDYMxz9/x3lg6zmhRWwq5T7qa1hXDOB6ffhFpxV0\n" + 
				"k1X5J0FC/YiVPg+8SgwUy5G9K4t9iPLVedoPddbYy07wpDrnPH1hAgMBAAE=\n" +
				"-----END RSA PUBLIC KEY-----";
		String privateKey = "-----BEGIN RSA PRIVATE KEY-----" +
				"MIICXAIBAAKBgQDbtl/Yo5SIQ22rmufsfQSv76257VOh0HNZTtUUQqUXyvQ1oZM8" +
				"ycCAAQZtTRFqUzeA4Ur9OKnGzKUs6kg2DMc/f8d5YOs5oUVsKuU+6mtYVwzgen34" +
				"RacVdJNV+SdBQv2IlT4PvEoMFMuRvSuLfYjy1XnaD3XW2MtO8KQ65zx9YQIDAQAB" +
				"AoGAeBtAVftGTR8fKroponvNPig1vffgygpbpCyWCtdLzK/jxBWpmYdothDZZJLG" +
				"vGr1YnzGM5rwJH7mpKEGDJX7rNVufTrcRIjquR2GFvhogNLr/I49XT2fehvgwjD1" +
				"7IxaQYU43wFazCyW5iKrdeAlVQ0luKJjawWofBYmRSHRWUkCQQDufDjcWYFMzJam" +
				"8CbCk6ZyM6jxcUOGfpzomHrK9NrCo/aryQ8Wuf0ka6IHaEJkX7CwSbGiRBfGtEex" +
				"HDdz+AofAkEA69kz5z1rhSOhDONTpZEdnI6tYThpnD1EQnHqnffhjCYUTzj6OnNs" +
				"BcaDnRz89QKFOaXR2V1hxPaeEvCd2lGIfwJAPFGvEAyTZ5lXgWG8a/psXvYyBN9g" +
				"9OORTENEy5CixBg0i76O0nC4Vj3i/XyhTkHlrrD0/NW8LcXrXCCG5g4WgQJAUqig" +
				"WUYcfeAb3MF7moZ+o1UaDP3RfdG3L7ZvLQgog48BBTcJ9Bxp2qhVjmYPfetxN+AW" +
				"6SCiWH66rhaorFBxDwJBAMoGgm9cxUCYsl2FQugr+wL0Kx8ECI5727TEzCmuVFUx" +
				"X+kXCiTBgiO0WtTnd/uQmtqcLi3w19ko2her4Ctm8/k=" +
				"-----END RSA PRIVATE KEY-----";
				*/
		
		String data = "hello world";
		BigInteger modulus = new BigInteger("128106353203760597946026513438279401195347353058108602297590493987905211076847937067111129027925324263858214597331164557918796912258346556117452344931343437998722064300025463940662353180549550506236793863671850655199947958325357726596455197764060005430188917295708428155243046292649974996733859136903115115777");
		BigInteger exponent = new BigInteger("65537");

		RSAPublicKeySpec pubKey = new RSAPublicKeySpec(modulus, exponent);
		Cipher c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		PKCS1Encoding pkcs1 = new PKCS1Encoding(c);

		KeyFactory keyFactory;
		keyFactory = KeyFactory.getInstance("RSA");
		Key key = keyFactory.generatePublic(pubKey);
		c.init(Cipher.DECRYPT_MODE, key);
		String cipherText = "8c079f46bf5d0f3dc26991993b48e121c4af991b5078f96ddb8c95a9f00c0c2236f2d9001ebda3d629ee64729d1b29ec8027238ce4f37b5e55535068a4e86f88a01823ff5545b144de159648af60c6cd0cbe9e8daa16e099eaa174e9b43798065b76e4ce200b46b65a70eb91991006a59fb4ea6c285e937d4f9625f366c4b3c1";
	//	BigInteger cipherAsBigInt = new BigInteger(cipherText, 16);
		byte[] cipherBytes = cipherAsBigInt.toByteArray();
		System.out.println(cipherBytes.length);
		byte[] plaintext = c.doFinal(cipherBytes);
		System.out.println("hex of data: " + bitsToHex(data.getBytes()));
		System.out.println("hex of decrypted: " + bitsToHex(plaintext));
		
	}
	
	public static byte[] hexStringToByteArray(String s) {
	    int len = s.length();
	    byte[] data = new byte[len / 2];
	    for (int i = 0; i < len; i += 2) {
	        data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
	                             + Character.digit(s.charAt(i+1), 16));
	    }
	    return data;
	}
	
	public static String bitsToHex(byte[] byteArray) {
		StringBuffer result = new StringBuffer();
		for (byte b:byteArray) {
			result.append(String.format("%02x", b));
		}
		return result.toString();
	}

}
