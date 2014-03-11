

public class TransactionOutput {

	private int value;
	private String key;
	private boolean used;
	
	public TransactionOutput(int value, String key) {
		this.value = value;
		this.key = key;
		used = false;
	}
	
	public int getValue() {
		return value;
	}
	
	public String getKey() {
		return key;
	}
	
	public boolean isUsed() {
		return used;
	}

	public void setUsed(boolean used) {
		this.used = used;
		
	}
	@Override
	public boolean equals(Object other) {
		if(other == null) return false;
		if(other == this) return true;
		if(!(other instanceof Transaction)) return false;
		TransactionOutput otherTransactionOutput = (TransactionOutput) other;
		if(this.getValue() == otherTransactionOutput.getValue() && this.getKey() == otherTransactionOutput.getKey()) {
			return true;
		} else {
			return false;
		}
	}
	
	@Override
	public int hashCode() {
		Integer a = new Integer(value);
		Integer b = new Integer(key);
		return a.hashCode() ^ b.hashCode();
	}
}
