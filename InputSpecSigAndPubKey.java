
public class InputSpecSigAndPubKey {
	private String publicKey;
	private byte[] signature;
	
	public InputSpecSigAndPubKey(String publicKey, byte[] signature) {
		this.publicKey = publicKey;
		this.signature = signature;
	}
	
	public String getPublicKey() {
		return publicKey;
	}
	
	public byte[] getSignature() {
		return signature;
	}
}
