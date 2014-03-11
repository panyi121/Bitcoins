import java.util.HashMap;
import java.util.Map;



public class Transaction {

	private String key;
	private Map<Integer,TransactionOutput> outputMap;
	public Transaction(String key) {
		this.key = key;
		outputMap = new HashMap<Integer,TransactionOutput>();
	}
	
	public String getKey() {
		return key;
	}
	
	public Map<Integer,TransactionOutput> getOutputMap() {
		return outputMap;
	}

	public void setOutputMap(Map<Integer,TransactionOutput> map) {
		outputMap = map;
	}
	@Override
	public boolean equals(Object other) {
		if(other == null) return false;
		if(other == this) return true;
		if(!(other instanceof Transaction)) return false;
		Transaction otherTransaction = (Transaction) other;
		if(this.getKey() == otherTransaction.getKey()) {
			return true;
		} else {
			return false;
		}
	}
	
	@Override
	public int hashCode() {
		Integer b = new Integer(key);
		return b.hashCode();
	}
}

