import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.Reader;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

public class Bitcoin {
	
	private static byte[] binaryData;
	private static int invalidTransactions;
	private static Cipher aes;
	private static int validTransactions;
	private static List<byte[]> transactionList;
	private static String genesisBlockName;
	private static Map<String,Integer> balancesMap;
	private static byte[] dHashOfGenesisBlock;
	private static Map<String,Map<Integer,TransactionOutput>> transactions;
	public static final int DIFFICULTY = 3;

	private static String identity = "-----BEGIN RSA PUBLIC KEY-----"+
									 "MIGJAoGBAN3MxXHcbc1VNKTOgdm7W+i/dVnjv8vYGlbkdaTKzYgi8rQm126Sri87"+
									 "702UBNzmkkZyKbRKL/Bfc4EG8/Mt9Pd2xQlRyXCL9FnIFWHyhfIQtW+oBsGI5UhG"+
									 "I8B8MiPOMfb6d/PdK+vd4riUxHAvCkHW5Lw0szAD1RVGbkG/7qnzAgMBAAE="+
									 "-----END RSA PUBLIC KEY-----";
	private static String identityBytes = "1f5a0200bc94ae4264642855786d9c2bb436b9e129ef95e6416136c03f339581";
	
	private static int txFee;
	
	public static void main(String[] args) throws Exception {
		txFee = 0;
	    binaryData = null;
	    balancesMap = new HashMap<String,Integer>();
	    invalidTransactions = 0;
	    validTransactions = 0;
		transactions = new HashMap<String,Map<Integer,TransactionOutput>>();
		transactionList = new LinkedList<byte[]>();
		try {
			Path path = Paths.get("./src/transactionData-10000-3.bin");
			binaryData = Files.readAllBytes(path);
			System.out.println(binaryData.length);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		try {
			aes = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
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
		System.out.println("transaction fee total: " + txFee);

		// Create block 1 header
		// before we calculate the merkle root we have to create the coinbase
		// transaction that gives us 10 bitcoins + tx fees because this is the first data item
		// used as input for the merkle root calculation
		// create a coinbase transaction.

		byte[] coinbase = new byte[40];
		// fill in the number of inputs, which is 0 because its a coinbase transaction
		ByteBuffer countBB = ByteBuffer.allocate(2);
		countBB.order(ByteOrder.LITTLE_ENDIAN);
		countBB.putShort((short)0);
		System.arraycopy(countBB, 0, coinbase, 0, 2);
		// fill in the number of outputs which is 1
		countBB.putShort(0, (short) 1);
		System.arraycopy(countBB, 0, coinbase, 2, 2);
		// fill in the value of this transaction, which is 10 + tx fees.
		// TODO INCLUDE TX FEES!!!!!
		ByteBuffer valBB = ByteBuffer.allocate(4);
		valBB.order(ByteOrder.LITTLE_ENDIAN);
		valBB.putInt(10);
		System.arraycopy(valBB, 0, coinbase, 4, 4);
		// calculate the dHash of our public key
		String pubkey = "-----BEGIN RSA PUBLIC KEY-----\nMIGJAoGBAN3MxXHcbc1VNKTOgdm7W+i/dVnjv8vYGlbkdaTKzYgi8rQm126Sri87\n702UBNzmkkZyKbRKL/Bfc4EG8/Mt9Pd2xQlRyXCL9FnIFWHyhfIQtW+oBsGI5UhG\nI8B8MiPOMfb6d/PdK+vd4riUxHAvCkHW5Lw0szAD1RVGbkG/7qnzAgMBAAE=\n-----END RSA PUBLIC KEY-----";
		Merkle m = new Merkle();
		byte[] hashedPubKey = m.dHash(pubkey.getBytes());
		// put it in the coinbase tx
		System.arraycopy(hashedPubKey, 0, coinbase, 8, hashedPubKey.length);
		// now put this at the front of the list of transactions so we can calculate the merkle root
		transactionList.add(0, hashedPubKey);
		// now we calculate the merkle root. 
		byte[] merkleRoot = m.calcMerkleRoot(transactionList);

		// build the header using the merkle root and start testing nonces
		byte[] header = new byte[82];
		// put the version number in the first 4 bytes
		ByteBuffer versionBB = ByteBuffer.allocate(4);
		versionBB.order(ByteOrder.LITTLE_ENDIAN);
		versionBB.putInt(1);
		byte[] versionBytes = versionBB.array();
		System.arraycopy(versionBytes, 0, header, 0, versionBytes.length);
		// copy in the genesis block name (its dHash value)
		System.arraycopy(dHashOfGenesisBlock, 0, header, 4, dHashOfGenesisBlock.length);
		// copy in the merkle root bytes
		System.arraycopy(merkleRoot, 0, header, 36, merkleRoot.length);
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

			// copy the time into the block header
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
		} while (!isAllZeros(first24bits)); 

		// we've found a nonce that works so we can build the output file then we are done
		System.out.println("found a nonce: " + nonce);
		
		for(String s: balancesMap.keySet()) {
			
			PrintWriter writer = new PrintWriter("balances.txt", "UTF-8");
			writer.println("Key: " + s);
			writer.println("Balance: " + balancesMap.get(s));
			writer.println();
			writer.close();
		}
		
	}

	public static boolean isAllZeros(byte[] input) {
		for (int i = 0; i < input.length; i++) {
			if (input[i] != 0x00) {
				return false;
			}
		}
		return true;
	}
	
	public static int processTransaction(int startIndex) throws Exception {
		// will change to false if the tx being processed is found to be invalid
		boolean valid = true;
		// loooks to be a mapping from tx name to indexes of output specifiers within this tx
		// that have been used as input specifiers
		Map<String,Set<Integer>> changedMap = new HashMap<String,Set<Integer>>();
		// a map from hashed public keys to signatures
		Map<String,byte[]> signatureMap = new HashMap<String,byte[]>();
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		//temporary map used to store changes in balance from this transaction, changes copied to main
		//balances map if transaction deemed valid
		Map<String,Integer> tempBalancesMap = new HashMap<String,Integer>();
		int currentIndex = startIndex;

		ByteBuffer numInputsBB = ByteBuffer.allocate(2);
		numInputsBB.order(ByteOrder.LITTLE_ENDIAN);
		numInputsBB.put(binaryData,currentIndex,2);
		int inputs = numInputsBB.getShort(0);
		System.out.println("Num Inputs: " + inputs);
		currentIndex += 2;
		int totalInputValue = 0;
		outputStream.write(getBytes(binaryData,0,2));
		/* iterate through the inputs and make sure that they:
		 * 1. all transactions referenced exist
		 * 2. the outputs referenced in the input specifiers actually exist (index exists)
		 * 3.
		 * 4.
		 */
		for(int i = 0; i < inputs; i++) {
			int inputStart = currentIndex;
			//System.out.println("Input:" + i+1);
			// get the name of the previous transaction this one references
			byte[] prevTransBytes = getBytes(binaryData,currentIndex,currentIndex+32);
			currentIndex +=32;
			String prevTxRef = bytesToHex(prevTransBytes);
			//System.out.println("Prev Trans Hash : " + prevTxRef);
			// get the index of the output specifier in the referenced transaction
			ByteBuffer indexBB = ByteBuffer.allocate(2);
			indexBB.order(ByteOrder.LITTLE_ENDIAN);
			indexBB.put(binaryData,currentIndex,2);
			int index = indexBB.getShort(0);
		//	System.out.println("Prev Trans index: " + index);
			currentIndex += 2;
			// get the signature of this transaction
			int signatureStart = currentIndex;
			byte[] signature = getBytes(binaryData,currentIndex,currentIndex+128);
			currentIndex += 128;
			int signatureEnd = currentIndex;
			// get the length of the public key
			ByteBuffer lengthBB = ByteBuffer.allocate(2);
			lengthBB.order(ByteOrder.LITTLE_ENDIAN);
			lengthBB.put(binaryData,currentIndex,2);
			int length = lengthBB.getShort(0);
			//System.out.println("Public key length: " + length);
			currentIndex+=2;
			// get the public key bytes
			byte[] inputKey = getBytes(binaryData,currentIndex,currentIndex+length);
			currentIndex+=length;
			int inputEnd = currentIndex;
			// write the entire input specifier minus the signature field
			outputStream.write(getBytes(binaryData,inputStart,signatureStart));
			outputStream.write(getBytes(binaryData,signatureEnd,inputEnd));
			
			if(transactions.containsKey(prevTxRef)) {
				//Transaction prev = transactions.get(s1);
				//Map<Integer,TransactionOutput> outputs = prev.getOutputMap();

				// a map from indexes to output specifiers and a flag indicating if it has been used yet
				Map<Integer,TransactionOutput> outputs2 = transactions.get(prevTxRef);
				// 
				if(!changedMap.containsKey(prevTxRef)) {
					changedMap.put(prevTxRef,new HashSet<Integer>());
				}
				if(outputs2.containsKey(index)) {
					// get the output spcecifier
					TransactionOutput output = outputs2.get(index);
					if(!output.isUsed()) {
						// compute the dHash of the public key supplied in the input specifier.
						String hashedInputKey = dHash(inputKey);
						// check that that hashed public key in the referenced output specifier matches
						// the hashed public key in the input specifier. Tx is invalid if they do not match
						if(hashedInputKey.equals(output.getKey())) {
							// add the mapping from the UNHASHED public key of the output referenced in the input to the
							// signature of the transaction
							signatureMap.put(new String(inputKey),signature);
							// add this index to the mapping from transaction names to indexes of output specifiers referenced
							changedMap.get(prevTxRef).add(index);
							int value = output.getValue();
							// transaction is valid so far, so increment its total value
							totalInputValue += value;
							
							//subtract value from key's balance
							if(!tempBalancesMap.containsKey(hashedInputKey)) {
								tempBalancesMap.put(hashedInputKey,0-value);
							} else {
								tempBalancesMap.put(hashedInputKey,tempBalancesMap.get(hashedInputKey)-value);
							}
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
		// now parsing the output specifiers
		int outputStart = currentIndex;
		ByteBuffer numOutputsBB = ByteBuffer.allocate(2);
		// get the number of entries
		numOutputsBB.order(ByteOrder.LITTLE_ENDIAN);
		numOutputsBB.put(binaryData,currentIndex,2);
		int outputs = numOutputsBB.getShort(0);
		//System.out.println("Num Outputs: " + outputs);
		currentIndex += 2;
		int totalOutputValue = 0;
		// a map from index to TransactionOutput, which stores the amount and the hashed public key of the recipient
		Map<Integer,TransactionOutput> outputMap = new HashMap<Integer,TransactionOutput>();
		// parse the outputs
		for(int i = 0; i < outputs; i++) {
			ByteBuffer outputValueBB = ByteBuffer.allocate(4);
			outputValueBB.order(ByteOrder.LITTLE_ENDIAN);
			outputValueBB.put(binaryData,currentIndex,4);
			int outputValue = outputValueBB.getInt(0);
			//System.out.println("Output Value: " + outputValue);
			currentIndex += 4;
			totalOutputValue += outputValue;
			byte[] hashedPublicKeyBytes = getBytes(binaryData,currentIndex,currentIndex+32);
			currentIndex +=32;
			String hexKey = bytesToHex(hashedPublicKeyBytes);
			TransactionOutput output = new TransactionOutput(outputValue,hexKey);
			outputMap.put(i,output);
			//subtract value from key's balance
			if(!tempBalancesMap.containsKey(hexKey)) {
				tempBalancesMap.put(hexKey,outputValue);
			} else {
				tempBalancesMap.put(hexKey,tempBalancesMap.get(hexKey)+outputValue);
			}
			
		}
		System.out.println(" Total Input Value: " + totalInputValue + " Total output value: " + totalOutputValue);
		if(totalOutputValue > totalInputValue) {
			System.out.println("Transaction invalid: Output value > input value, write code to deal with this");
			valid = false;
		} 
		// increment the transaction fee
		if (totalOutputValue < totalInputValue) {
			txFee += totalInputValue - totalOutputValue;
		}

		outputStream.write(getBytes(binaryData,outputStart,currentIndex));
		String transactionHash = dHash(getBytes(binaryData,startIndex,currentIndex));
		//transactions.put(transactionHash,current);
		// should we break before getting here? if it's invalid then we're done with it 
		if (valid) {
			byte[] transactionBytes = outputStream.toByteArray();
			String newHash = dHash(transactionBytes);
			
			for(String key: signatureMap.keySet()) {
				// we need to decrypt the signature field of each input specifier using the supplied
				// public key and make sure that the data equals the dHash of the the entire transaction
				// minus the signature fields.
				byte[] signature = signatureMap.get(key);
				System.out.println("signature length: " + signature.length);
				System.out.println(key);
				RSAPublicKey publicKey = getKey(key);
				aes.init(Cipher.DECRYPT_MODE, publicKey);
				// this should be the dHash of the entire tx
				byte[] plaintext = aes.doFinal(signature);
				System.out.println("decrypted signature: " + bytesToHex(plaintext));
				System.out.println("dHash of tx: " + newHash);
				
				if (!newHash.equals(bytesToHex(plaintext))) {

					invalidTransactions++;
					valid = false;
					break;
				}
				
			}
			if (valid) {
				System.out.println("transaction valid");
				for(String hexKey: tempBalancesMap.keySet()) {
					if(!balancesMap.containsKey(hexKey)) {
						balancesMap.put(hexKey,tempBalancesMap.get(hexKey));
					} else {
						balancesMap.put(hexKey,balancesMap.get(hexKey)+tempBalancesMap.get(hexKey));
					}
				}

				validTransactions++;
				transactionList.add(getBytes(binaryData,startIndex,currentIndex));
				transactions.put(transactionHash, outputMap);
				for(String s: changedMap.keySet()) {
					Set<Integer> indexSet = changedMap.get(s);
					for(Integer i: indexSet) {
						transactions.get(s).get(i).setUsed(true);
					}
				}
			}
		} else {
			invalidTransactions++;
		}
		return currentIndex;
	}
	   public static RSAPublicKey getKey(String key) throws Exception {
		      Object o;
		      PEMParser pemRd = openPEMResource(key);
		      RSAPublicKey myKey = null;
		      while ((o = pemRd.readObject()) != null) {
		         if (o instanceof SubjectPublicKeyInfo) {
		            JcaPEMKeyConverter myConverter = new JcaPEMKeyConverter();
		            myKey = (RSAPublicKey) myConverter.getPublicKey((SubjectPublicKeyInfo) o);
		            /*
		            BigInteger exponent = myKey.getPublicExponent();
		            BigInteger modulus = myKey.getModulus();
		            System.out.println("Exponent:");
		            System.out.println(exponent);
		            System.out.println("Modulus:");
		            System.out.println(modulus);
		            */
		         } else {
		            System.out.println("Not an instance of SubjectPublicKeyInfo.");
		         }
		      }
		      return myKey;
		   }

	private static PEMParser openPEMResource(String key) throws FileNotFoundException {
		Reader fRd = new BufferedReader(new InputStreamReader(new ByteArrayInputStream(key.getBytes())));
		return new PEMParser(fRd);
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
		// set the field for the hash of the genesis block to the hash of the entire genesis block
		// this is used for creating the next block header
		byte[] genBlock = new byte[82];
		System.arraycopy(binaryData, 0, genBlock, 0, genBlock.length);
		Merkle m = new Merkle();
		dHashOfGenesisBlock = m.dHash(genBlock);
		System.out.println("Block: dHash (name) = " + dHash(genBlock));
		
		// get the version number
		ByteBuffer versionBB = ByteBuffer.allocate(4);
		versionBB.order(ByteOrder.LITTLE_ENDIAN);
		versionBB.put(binaryData, 0, 4);
		System.out.println("Version: " + versionBB.getInt(0));
	
		// get the previous block hash which should be zero
		byte[] prevBlockBytes = getBytes(binaryData,4,36);
		String s1 = bytesToHex(prevBlockBytes);
		System.out.println("Prev Block Hash : " + s1);
	
		// get the merkle root
		byte[] merkleBytes = getBytes(binaryData,36,68);
		String s2 = bytesToHex(merkleBytes);
		System.out.println("Merkle : " + s2);
		
		// get the creation time
		ByteBuffer creationTimeBB = ByteBuffer.allocate(4);
		creationTimeBB.order(ByteOrder.LITTLE_ENDIAN);
		creationTimeBB.put(binaryData,68,4);
		System.out.println("Creation Time: " + creationTimeBB.getInt(0));
	
		// get the difficulty
		ByteBuffer difficultyBB = ByteBuffer.allocate(2);
		difficultyBB.order(ByteOrder.LITTLE_ENDIAN);
		difficultyBB.put(binaryData,72,2);
		System.out.println("Difficulty: " + difficultyBB.getShort(0));
	
		// get the nonce
		ByteBuffer nonceBB = ByteBuffer.allocate(8);
		nonceBB.order(ByteOrder.LITTLE_ENDIAN);
		nonceBB.put(binaryData,74,8);
		System.out.println("Nonce: " + nonceBB.getLong(0));
	
		// get the genesis block transaction count, should be 1
		ByteBuffer numTransactionsTimeBB = ByteBuffer.allocate(4);
		numTransactionsTimeBB.order(ByteOrder.LITTLE_ENDIAN);
		numTransactionsTimeBB.put(binaryData,82,4);
		System.out.println("\nnumTransactions: " + numTransactionsTimeBB.getInt(0));
	
		// now we are examining the coinbase transaction

		// get the number of input specifiers. should be zero because its a coinbase transaction
		ByteBuffer numInputsBB = ByteBuffer.allocate(2);
		numInputsBB.order(ByteOrder.LITTLE_ENDIAN);
		numInputsBB.put(binaryData,86,2);
		System.out.println("numInputs: " + numInputsBB.getShort(0));
	
		// get the number of outputs, should be one
		ByteBuffer numOutputsBB = ByteBuffer.allocate(2);
		numOutputsBB.order(ByteOrder.LITTLE_ENDIAN);
		numOutputsBB.put(binaryData,88,2);
		System.out.println("numOutputs: " + numOutputsBB.getShort(0));
	
		// get the value of this coinbase output
		ByteBuffer valueBB = ByteBuffer.allocate(4);
		valueBB.order(ByteOrder.LITTLE_ENDIAN);
		valueBB.put(binaryData,90,4);
		System.out.println("Value: " + valueBB.getInt(0));
	
		// 
		byte[] hashedPublicKeyBytes = getBytes(binaryData,94,126);
		String s3 = bytesToHex(hashedPublicKeyBytes);
		System.out.println("Hashed Public Key : " + s3);
		
		TransactionOutput genesisOutput = new TransactionOutput(valueBB.getInt(0),s3);
		

		Map<Integer, TransactionOutput> genesisOutputMap= new HashMap<Integer,TransactionOutput>();
		genesisOutputMap.put(0, genesisOutput);

		transactions.put(s2,genesisOutputMap);
		// should this be included?????
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

