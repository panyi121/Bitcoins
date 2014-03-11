import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class Bitcoin {
	
	//private static Map<String,Transaction> transactions;
	private static Map<String,Map<Integer,TransactionOutput>> transactions2;
	private static byte[] binaryData;
	private static int invalidTransactions;
	private static int validTransactions;
	private static int noInputTransactions;
	public static void main(String[] args) {
	    binaryData = null;
	    invalidTransactions = 0;
	    validTransactions = 0;
	    noInputTransactions = 0;
		//transactions = new HashMap<String,Transaction>();
		transactions2 = new HashMap<String,Map<Integer,TransactionOutput>>();
		try {
			Path path = Paths.get("./src/transactionData-10000-3.bin");
			binaryData = Files.readAllBytes(path);
			System.out.println(binaryData.length);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		parseGenesis();
		System.out.println();
		ByteBuffer numTransactionsBB = ByteBuffer.allocate(4);
		numTransactionsBB.order(ByteOrder.LITTLE_ENDIAN);
		numTransactionsBB.put(binaryData,126,4);
		int numTransactions = numTransactionsBB.getInt(0);
		System.out.println("numTransactions: " + numTransactions+"\n");
		int currentIndex = 130;
		for(int i = 0; i < numTransactions; i++) {
			System.out.println(i+1);
			currentIndex = processTransaction(currentIndex);
			
		}
		System.out.println(invalidTransactions);
		System.out.println(validTransactions);
	}
	
	public static int processTransaction(int startIndex) {
		boolean valid = true;
		Map<String,Set<Integer>> changedMap = new HashMap<String,Set<Integer>>();
		int currentIndex = startIndex;
		ByteBuffer numInputsBB = ByteBuffer.allocate(2);
		numInputsBB.order(ByteOrder.LITTLE_ENDIAN);
		numInputsBB.put(binaryData,currentIndex,2);
		int inputs = numInputsBB.getShort(0);
		System.out.println("Num Inputs: " + inputs);
		currentIndex += 2;
		int totalInputValue = 0;
		for(int i = 0; i < inputs; i++) {
			System.out.println("Input:" + i+1);
			byte[] prevTransBytes = getBytes(binaryData,currentIndex,currentIndex+32);
			currentIndex +=32;
			String s1 = bytesToHex(prevTransBytes);
			System.out.println("Prev Trans Hash : " + s1);
			ByteBuffer indexBB = ByteBuffer.allocate(2);
			indexBB.order(ByteOrder.LITTLE_ENDIAN);
			indexBB.put(binaryData,currentIndex,2);
			int index = indexBB.getShort(0);
			System.out.println("Prev Trans index: " + index);
			currentIndex += 2;
			currentIndex += 128;
			ByteBuffer lengthBB = ByteBuffer.allocate(2);
			lengthBB.order(ByteOrder.LITTLE_ENDIAN);
			lengthBB.put(binaryData,currentIndex,2);
			int length = lengthBB.getShort(0);
			System.out.println("Public key length: " + length);
			currentIndex+=2;
			byte[] inputKey = getBytes(binaryData,currentIndex,currentIndex+length);
			currentIndex+=length;
			
			if(transactions2.containsKey(s1)) {
				//Transaction prev = transactions.get(s1);
				//Map<Integer,TransactionOutput> outputs = prev.getOutputMap();
				Map<Integer,TransactionOutput> outputs2 = transactions2.get(s1);
				if(!changedMap.containsKey(s1)) {
					changedMap.put(s1,new HashSet<Integer>());
				}
				if(outputs2.containsKey(index)) {
					TransactionOutput output = outputs2.get(index);
					if(!output.isUsed()) {
						String hashedInputKey = dHash(inputKey);
						if(hashedInputKey.equals(output.getKey())) {
							changedMap.get(s1).add(index);
							int value = output.getValue();
							totalInputValue += value;
						} else {
							System.out.println("Transaction invalid: Hashed input key does not equal hashed output key");
							valid = false;
						}
					} else { 
						System.out.println("Transaction invalid: Output already used before, write code to deal with this");
						valid = false;
					}
				} else {
					System.out.println("Transaction invalid: Index not found in transaction's output map, write code to deal with this");
					valid = false;
				}
			} else {
				System.out.println("Transaction invalid: Key not found, write code to deal with this");
				valid = false;
			}
		}
		ByteBuffer numOutputsBB = ByteBuffer.allocate(2);
		numOutputsBB.order(ByteOrder.LITTLE_ENDIAN);
		numOutputsBB.put(binaryData,currentIndex,2);
		int outputs = numOutputsBB.getShort(0);
		System.out.println("Num Outputs: " + outputs);
		currentIndex += 2;
		int totalOutputValue = 0;
		Map<Integer,TransactionOutput> outputMap = new HashMap<Integer,TransactionOutput>();
		for(int i = 0; i < outputs; i++) {
			ByteBuffer outputValueBB = ByteBuffer.allocate(4);
			outputValueBB.order(ByteOrder.LITTLE_ENDIAN);
			outputValueBB.put(binaryData,currentIndex,4);
			int outputValue = outputValueBB.getInt(0);
			System.out.println("Output Value: " + outputValue);
			currentIndex += 4;
			totalOutputValue += outputValue;
			byte[] hashedPublicKeyBytes = getBytes(binaryData,currentIndex,currentIndex+32);
			currentIndex +=32;
			String s1 = bytesToHex(hashedPublicKeyBytes);
			TransactionOutput output = new TransactionOutput(outputValue,s1);
			outputMap.put(i,output);
		}
		System.out.println(" Total Input Value: " + totalInputValue + " Total output value: " + totalOutputValue);
		if(totalOutputValue > totalInputValue) {
			System.out.println("Transaction invalid: Output value > input value, write code to deal with this");
			valid = false;
		}
		
		String transactionHash = dHash(getBytes(binaryData,startIndex,currentIndex));
		Transaction current = new Transaction(transactionHash);
		current.setOutputMap(outputMap);
		//transactions.put(transactionHash,current);
		if(valid) {
			validTransactions++;
			transactions2.put(transactionHash, outputMap);
			for(String s: changedMap.keySet()) {
				Set<Integer> indexSet = changedMap.get(s);
				for(Integer i: indexSet) {
					transactions2.get(s).get(i).setUsed(true);
				}
			}
		} else {
			invalidTransactions++;
		}
		return currentIndex;
	}


	public static String dHash(byte[] bytes) {
		MessageDigest md = null;
		try {
			md = MessageDigest.getInstance("SHA-256");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		md.update(bytes);
		byte[] byteArray = md.digest();
		md.update(byteArray);
		byteArray = md.digest();
		StringBuffer result = new StringBuffer();
		for (byte b:byteArray) {
		    result.append(String.format("%02x", b));
		}
		
		return result.toString();
	}
		
	
	public static void parseGenesis() {
		ByteBuffer versionBB = ByteBuffer.allocate(4);
		versionBB.order(ByteOrder.LITTLE_ENDIAN);
		versionBB.put(binaryData, 0, 4);
		System.out.println("Version: " + versionBB.getInt(0));
		
		byte[] prevBlockBytes = getBytes(binaryData,4,36);
		String s1 = bytesToHex(prevBlockBytes);
		System.out.println("Prev Block Hash : " + s1);
		
		byte[] merkleBytes = getBytes(binaryData,36,68);
		String s2 = bytesToHex(merkleBytes);
		System.out.println("Merkle : " + s2);
		
		ByteBuffer creationTimeBB = ByteBuffer.allocate(4);
		creationTimeBB.order(ByteOrder.LITTLE_ENDIAN);
		creationTimeBB.put(binaryData,68,4);
		System.out.println("Creation Time: " + creationTimeBB.getInt(0));
		
		ByteBuffer difficultyBB = ByteBuffer.allocate(2);
		difficultyBB.order(ByteOrder.LITTLE_ENDIAN);
		difficultyBB.put(binaryData,72,2);
		System.out.println("Difficulty: " + difficultyBB.getShort(0));
		
		ByteBuffer nonceBB = ByteBuffer.allocate(8);
		nonceBB.order(ByteOrder.LITTLE_ENDIAN);
		nonceBB.put(binaryData,74,8);
		System.out.println("Nonce: " + nonceBB.getLong(0));
		
		ByteBuffer numTransactionsTimeBB = ByteBuffer.allocate(4);
		numTransactionsTimeBB.order(ByteOrder.LITTLE_ENDIAN);
		numTransactionsTimeBB.put(binaryData,82,4);
		System.out.println("\nnumTransactions: " + numTransactionsTimeBB.getInt(0));
		
		ByteBuffer numInputsBB = ByteBuffer.allocate(2);
		numInputsBB.order(ByteOrder.LITTLE_ENDIAN);
		numInputsBB.put(binaryData,86,2);
		System.out.println("numInputs: " + numInputsBB.getShort(0));
		
		ByteBuffer numOutputsBB = ByteBuffer.allocate(2);
		numOutputsBB.order(ByteOrder.LITTLE_ENDIAN);
		numOutputsBB.put(binaryData,88,2);
		System.out.println("numOutputs: " + numOutputsBB.getShort(0));
		
		ByteBuffer valueBB = ByteBuffer.allocate(4);
		valueBB.order(ByteOrder.LITTLE_ENDIAN);
		valueBB.put(binaryData,90,4);
		System.out.println("Value: " + valueBB.getInt(0));
		
		byte[] hashedPublicKeyBytes = getBytes(binaryData,94,126);
		String s3 = bytesToHex(hashedPublicKeyBytes);
		System.out.println("Hashed Public Key : " + s3);
		
		TransactionOutput genesisOutput = new TransactionOutput(valueBB.getInt(0),s3);
		
		Transaction genesis = new Transaction(s2);
		Map<Integer,TransactionOutput> genesisOutputMap = genesis.getOutputMap();
		genesisOutputMap.put(0, genesisOutput);
		//transactions.put(s2,genesis);
		transactions2.put(s2,genesisOutputMap);
	}
	public static String bytesToHex(byte[] in) {
	    final StringBuilder builder = new StringBuilder();
	    for(byte b : in) {
	        builder.append(String.format("%02x", b));
	    }
	    return builder.toString();
	}
	
	private static byte[] getBytes(byte[] src, int start, int end) {
		byte[] bb = new byte[end - start];
		System.arraycopy(src, start, bb, 0, end - start);
		return bb;
	}
}

