
import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class Bitcoin {
	
	private static byte[] binaryData;
	private static int invalidTransactions;
	private static int validTransactions;
	private static List<byte[]> transactionList;
	private static String genesisBlockName;
	
	private static Map<String,Map<Integer,TransactionOutput>> transactions;
	public static final int DIFFICULTY = 3;

	public static void main(String[] args) {
	    binaryData = null;
	    invalidTransactions = 0;
	    validTransactions = 0;
		transactions = new HashMap<String,Map<Integer,TransactionOutput>>();
		transactionList = new ArrayList<byte[]>();
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
		
		// now we calculate the merkle root
		Merkle m = new Merkle();
		byte[] merkleRoot = m.calcMerkleRoot(transactionList);
		// build the header using the merkle root and start testing nonces
		byte[] header = new byte[82];
		// put the version number in the first 4 bytes
		ByteBuffer versionBB = ByteBuffer.allocate(4);
		versionBB.order(ByteOrder.LITTLE_ENDIAN);
		versionBB.putInt(1);
		byte[] versionBytes = versionBB.array();
		System.arraycopy(versionBytes, 0, header, 0, versionBytes.length);
		// copy in the genesis block name
		byte[] genesisNameBytes = genesisBlockName.getBytes();
		System.arraycopy(genesisNameBytes, 0, header, 4, genesisNameBytes.length);
		// copy in the merkle root bytes
		System.arraycopy(merkleRoot, 0, header, 4, merkleRoot.length);
		// copy in the difficulty
		ByteBuffer difficultyBB = ByteBuffer.allocate(2);
		difficultyBB.order(ByteOrder.LITTLE_ENDIAN);
		difficultyBB.putShort((short)3);
		byte[] difficultyBytes = difficultyBB.array();
		System.arraycopy(difficultyBytes, 0, header, 72, difficultyBytes.length);
		// start 
		long nonce = Long.MIN_VALUE;
		byte[] first24bits = new byte[3];
		
		do {
			// get the current time
			long time = System.currentTimeMillis();
			// convert it to seconds
			time /= 1000;
			int timeInSeconds = (int) time; 
			ByteBuffer timeBB = ByteBuffer.allocate(4);
			timeBB.order(ByteOrder.LITTLE_ENDIAN);
			timeBB.putInt(timeInSeconds);
			byte[] timeBytes = timeBB.array();
			// copy the time into the header
			System.arraycopy(timeBytes, 0, header, 68, timeBytes.length);

			// copy the nonce into the header
			ByteBuffer nonceBB = ByteBuffer.allocate(8);
			nonceBB.order(ByteOrder.LITTLE_ENDIAN);
			nonceBB.putLong(nonce);
			byte[] nonceBytes = nonceBB.array();
			System.arraycopy(nonceBytes, 0, header, 74, nonceBytes.length);
			
			byte[] hash = m.dHash(header);
			System.arraycopy(hash, hash.length - DIFFICULTY, first24bits, 0, DIFFICULTY);
			nonce++;
		} while (!isAllZeros(first24bits)); /* while the  */
		// we've found a nonce that works so we can add the block header
		System.out.println("found a nonce: " + nonce);

		// create a coinbase transaction.
		byte[] coinbase = new byte[40];
		// fill in the number of inputs, which is 0 because its a coinbase transaction
		ByteBuffer countBB = ByteBuffer.allocate(0);
		countBB.order(ByteOrder.LITTLE_ENDIAN);
		countBB.putShort((short)0);
		System.arraycopy(countBB, 0, coinbase, 0, 2);
		// fill in the number of outputs which is 1
		countBB.putShort(0, (short) 0);

		String pubkey = "-----BEGIN RSA PUBLIC KEY-----\nMIGJAoGBAN3MxXHcbc1VNKTOgdm7W+i/dVnjv8vYGlbkdaTKzYgi8rQm126Sri87\n702UBNzmkkZyKbRKL/Bfc4EG8/Mt9Pd2xQlRyXCL9FnIFWHyhfIQtW+oBsGI5UhG\nI8B8MiPOMfb6d/PdK+vd4riUxHAvCkHW5Lw0szAD1RVGbkG/7qnzAgMBAAE=\n-----END RSA PUBLIC KEY-----";
		// dHash it
		byte[] hashedPubKey = m.dHash(pubkey.getBytes());
		
	}

	public static boolean isAllZeros(byte[] input) {
		for (int i = 0; i < input.length; i++) {
			if (input[i] != 0x00) {
				return false;
			}
		}
		return true;
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
			
			if(transactions.containsKey(s1)) {
				//Transaction prev = transactions.get(s1);
				//Map<Integer,TransactionOutput> outputs = prev.getOutputMap();
				Map<Integer,TransactionOutput> outputs2 = transactions.get(s1);
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
			transactionList.add(getBytes(binaryData,startIndex,currentIndex));
			transactions.put(transactionHash, outputMap);
			for(String s: changedMap.keySet()) {
				Set<Integer> indexSet = changedMap.get(s);
				for(Integer i: indexSet) {
					transactions.get(s).get(i).setUsed(true);
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
		genesisBlockName = s2;
		
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

		transactions.put(s2,genesisOutputMap);
		transactionList.add(getBytes(binaryData,0,126));
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

