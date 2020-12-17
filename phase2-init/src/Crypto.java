import java.security.Security;

import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.BlowfishEngine;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Base64;


import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;

public class Crypto {

	
	public static String generateRandomString(int byteLength) {
	    SecureRandom secureRandom = new SecureRandom();
	    byte[] token = new byte[byteLength];
	    secureRandom.nextBytes(token);
	    return new String(Base64.encode(token));
	}

	public static byte[] generateRandomBytes(int byteLength) {
	    SecureRandom secureRandom = new SecureRandom();
	    byte[] token = new byte[byteLength];
	    secureRandom.nextBytes(token);
	    return token;
	}

	class SHA256{
		public String messageDigest(String message) {
			try {
			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

		    
		    MessageDigest md = MessageDigest.getInstance("SHA-256");
		    md.update(message.getBytes("UTF-8"));
		    byte[] digest = md.digest();
		    return new String(Base64.encode(digest));
			} catch (Exception e) 
			  {
			    e.printStackTrace();
			    return null;
			  }
		}
		
	}
	class AES{
		private PaddedBufferedBlockCipher cipher;
		private ParametersWithIV keyParamWithIV;
	public AES() {
		//INITIALIZING ENGINE
		try {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", "BC");

        keyGenerator.init(128);
        SecretKey key = keyGenerator.generateKey();
        System.out.println("\nAES - Generated key (encoded in B64): " + Base64.encode(key.getEncoded()));
      
        byte[] iv = new byte[16]; // 128/8
        Random r = new Random(); // Note: no  seed here, ie these values are truly random
        r.nextBytes(iv);
        System.out.println("\nAES - Generated IV (encoded in B64): " + new String(Base64.encode(iv)));
        
    	//engine setup
		AESEngine engine = new AESEngine();
		CBCBlockCipher blockCipher = new CBCBlockCipher(engine); 
		PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(blockCipher); 
		this.cipher = cipher;
		KeyParameter keyParam = new KeyParameter(key.getEncoded());
		
		ParametersWithIV keyParamWithIV = new ParametersWithIV(keyParam, iv, 0, 16);
		this.keyParamWithIV = keyParamWithIV;
		//Usage example:
    	//String ciphertext = AESEncrypt(plaintext, key, cipher, keyParamWithIV);
		} catch (Exception e) 
		  {
		    e.printStackTrace();
		  }
	}

	// init 256-bit AES with a shared secret
	public AES(byte[] bytesKey, byte[] iv) {
		// byte[] sharedSecret = sharedSecretDH.getBytes();
		// System.out.println(sharedSecret.length);
		// SecureRandom random = new SecureRandom(sharedSecret);
		// byte[] bytesKey = new byte[32]; // 256-bit
		// byte[] iv = new byte[16];
		// random.nextBytes(bytesKey);
		// random.nextBytes(iv);
		try {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		
        SecretKey key = new SecretKeySpec(bytesKey, 0, bytesKey.length, "AES");
        System.out.println("\nAES - Generated key (encoded in B64): " + Base64.encode(key.getEncoded()));
        System.out.println("\nAES - Generated IV (encoded in B64): " + new String(Base64.encode(iv)));
        
    	//engine setup
		AESEngine engine = new AESEngine();
		CBCBlockCipher blockCipher = new CBCBlockCipher(engine); 
		PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(blockCipher); 
		this.cipher = cipher;
		KeyParameter keyParam = new KeyParameter(key.getEncoded());
		
		ParametersWithIV keyParamWithIV = new ParametersWithIV(keyParam, iv, 0, 16);
		this.keyParamWithIV = keyParamWithIV;
		//Usage example:
    	//String ciphertext = AESEncrypt(plaintext, key, cipher, keyParamWithIV);
		} catch (Exception e) 
		  {
		    e.printStackTrace();
		  }
	}

	public String AESEncrypt(String plaintext) {
		try {	
    	
    	byte[] inputBytes = plaintext.getBytes("UTF-8");
    	int length;
		// Encrypt
        cipher.init(true, keyParamWithIV);
        byte[] outputBytes = new byte[cipher.getOutputSize(inputBytes.length)];
        length = cipher.processBytes(inputBytes,0,inputBytes.length, outputBytes, 0);
        cipher.doFinal(outputBytes, length); 
        String encryptedInput = new String(Base64.encode(outputBytes));
        return encryptedInput;
		}
		catch (Exception e) 
		  {
		    e.printStackTrace();
		    return "";
		  }

	}

	public byte[] AESEncryptBytes(byte[] inputBytes) {
		try {	
    	
    	int length;
		// Encrypt
        cipher.init(true, keyParamWithIV);
        byte[] outputBytes = new byte[cipher.getOutputSize(inputBytes.length)];
        length = cipher.processBytes(inputBytes,0,inputBytes.length, outputBytes, 0);
        cipher.doFinal(outputBytes, length); 
        return outputBytes;
		}
		catch (Exception e) 
		  {
		    e.printStackTrace();
		    return null;
		  }

	}

	public String AESDecrypt(String ciphertext) {
		try {
		
    	
		int length;
		//Decrypt            
        cipher.init(false, keyParamWithIV);
        byte[] out2 = Base64.decode(ciphertext);
        byte[] comparisonBytes = new byte[cipher.getOutputSize(out2.length)];
        length = cipher.processBytes(out2, 0, out2.length, comparisonBytes, 0);
        cipher.doFinal(comparisonBytes, length); //Do the final block
        String s2 = new String(comparisonBytes);
        return s2;
		}
		catch (Exception e) 
		  {
		    e.printStackTrace();
		    return "";
		  }
	}

	public byte[] AESDecryptBytes(byte[] out2) {
		try {
		
    	
		int length;
		//Decrypt            
        cipher.init(false, keyParamWithIV);
        byte[] comparisonBytes = new byte[cipher.getOutputSize(out2.length)];
        length = cipher.processBytes(out2, 0, out2.length, comparisonBytes, 0);
        cipher.doFinal(comparisonBytes, length); //Do the final block
        return comparisonBytes;
		}
		catch (Exception e) 
		  {
		    e.printStackTrace();
		    return null;
		  }
	}
	
	public boolean decryptFile(String filePath, String key, int hashChainIndex) {
		try
		{
		    FileInputStream fileInputStream = new FileInputStream(filePath);
		    byte[] buffer = new byte[fileInputStream.available()];
		    int length = fileInputStream.read(buffer);
		    fileInputStream.close();
		    String fileString = new String(buffer, 0, length, StandardCharsets.UTF_8);
		    //get the right decryption key and IV
		    int encryptionHashIndex = Integer.parseInt(fileString.split("__HASHINDEX__=")[1]);
		    String encryptedFile = fileString.split("__HASHINDEX__=")[0];
		    SHA256 DigestProvider = new SHA256();
		    if(hashChainIndex != encryptionHashIndex) {
		    	if(hashChainIndex < encryptionHashIndex) {
		    		System.out.println("Group key updated since last time your token was issued. You need a new token or you're not part of the group anymore");
		    		return false;
		    	}
		    	while(hashChainIndex != encryptionHashIndex) {
		    		key = DigestProvider.messageDigest(key);
		    		hashChainIndex--;
		    	}
		    	KeyParameter keyParam = new KeyParameter(key.getBytes());
				
				ParametersWithIV keyParamWithIV = new ParametersWithIV(keyParam, Arrays.copyOfRange(key.getBytes(), 0, 16), 0, 16);
				this.keyParamWithIV = keyParamWithIV;
				System.out.println("Decrypting file with key: " + key + " and IV: " + Arrays.copyOfRange(key.getBytes(), 0, 16));

		    }
		    String decryptedFile = this.AESDecrypt(encryptedFile);
		    
		    
		    fileString = this.AESEncrypt(fileString);
		    
		    
		    File f = new File(filePath);
		    
		    f.delete();//delete encrypted file
		    
		    
		    f.createNewFile();
		    FileWriter writer = new FileWriter(filePath);
		    writer.append(decryptedFile);
		    writer.flush();
		    writer.close();
		    return true;
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
		
	}
	
	public boolean encryptFile(String filePath, String key, int hashChainIndex) {
		
		try
		{
		    FileInputStream fileInputStream = new FileInputStream(filePath);
		    byte[] buffer = new byte[fileInputStream.available()];
		    int length = fileInputStream.read(buffer);
		    fileInputStream.close();
		    String fileString = new String(buffer, 0, length, StandardCharsets.UTF_8);
			System.out.println("Encrypting file with key: " + key + " and IV: " + Arrays.copyOfRange(key.getBytes(), 0, 16));

		    fileString = this.AESEncrypt(fileString);
		    fileString += "__HASHINDEX__=" + hashChainIndex;
		    File f = new File(filePath + ".enc");
		    if (f.exists()) {
		    	f.delete();
		    }
		    f.createNewFile();
		    FileWriter writer = new FileWriter(filePath + ".enc");
		    writer.append(fileString);
		    writer.flush();
		    writer.close();
		    return true;
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
	}
	
	}
	
	class RSA{
		public String pubKeyFilename;
		public String privKeyFilename;
		public RSA() {
			pubKeyFilename = "pubkey";
			privKeyFilename = "privkey";
		}
		public RSA(String pubKeyFileName, String privKeyFileName) {
			pubKeyFilename = pubKeyFileName;
			privKeyFilename = privKeyFileName;
		}
		
		public boolean storeRSAKey(byte[] key, String fileName, boolean isPublic) {
			try {
			BufferedWriter out = new BufferedWriter(new FileWriter(fileName));
            out.write(new String(java.util.Base64.getMimeEncoder().encode(key), StandardCharsets.UTF_8));
            out.close();
			} catch(Exception e) {}
			return false;
		}
		
		public void generateRSAKeys(){
	 
	   
	        generate(pubKeyFilename, privKeyFilename);
	 
	    }
	 
		private void generate (String publicKeyFilename, String privateKeyFilename){
	 
	        try {
	 
	            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	 
	            // Create the public and private keys
	            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
	         
	 
	            SecureRandom random = createFixedRandom();
	            generator.initialize(4096, random);
	 
	            KeyPair pair = generator.generateKeyPair();
	            Key pubKey = pair.getPublic();
	            Key privKey = pair.getPrivate();
	            
	            System.out.println("\npublicKey : " + new String(java.util.Base64.getMimeEncoder().encode(pubKey.getEncoded()),
                        StandardCharsets.UTF_8));
	            System.out.println("\nprivateKey : " + new String(java.util.Base64.getMimeEncoder().encode(privKey.getEncoded()),
                        StandardCharsets.UTF_8));
	 
	            BufferedWriter out = new BufferedWriter(new FileWriter(publicKeyFilename));
	            out.write(new String(java.util.Base64.getMimeEncoder().encode(pubKey.getEncoded()),
                        StandardCharsets.UTF_8));
	            out.close();
	 
	            out = new BufferedWriter(new FileWriter(privateKeyFilename));
	            out.write(new String(java.util.Base64.getMimeEncoder().encode(privKey.getEncoded()),
                        StandardCharsets.UTF_8));
	            out.close();
	 
	 
	        }
	        catch (Exception e) {
	            System.out.println(e);
	        }
	    }
	 
	    public SecureRandom createFixedRandom(){
	        return new FixedRand();
	    }
	 
	    private class FixedRand extends SecureRandom {
	 
	        MessageDigest sha;
	        byte[] state;
	 
	        FixedRand() {
	            try
	            {
	                this.sha = MessageDigest.getInstance("SHA-1");
	                this.state = sha.digest();
	            }
	            catch (NoSuchAlgorithmException e)
	            {
	                throw new RuntimeException("can't find SHA-1!");
	            }
	    }
	 
	    public void nextBytes(byte[] bytes){
	 
	            int    off = 0;
	 
	            sha.update(state);
	 
	            while (off < bytes.length)
	            {                
	                state = sha.digest();
	 
	                if (bytes.length - off > state.length)
	                {
	                    System.arraycopy(state, 0, bytes, off, state.length);
	                }
	                else
	                {
	                    System.arraycopy(state, 0, bytes, off, bytes.length - off);
	                }
	 
	                off += state.length;
	 
	                sha.update(state);
	            }
	        }
	    }
	    
	   
	 
	    public String RSAEncrypt (String keyFileName, String inputData, boolean rsaSign){
			 
	        String encryptedData = null;
	        try {
	 
	            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	            String key = readFileAsString(keyFileName);
	            
	            AsymmetricKeyParameter encryptionKey;
	            if(rsaSign) {
	            	encryptionKey = (AsymmetricKeyParameter) PrivateKeyFactory.createKey(Base64.decode(key));
	            } else {
	            	encryptionKey = (AsymmetricKeyParameter) PublicKeyFactory.createKey(Base64.decode(key));
	            }
	            
	            
	            AsymmetricBlockCipher e = new RSAEngine();
	            e = new org.bouncycastle.crypto.encodings.PKCS1Encoding(e);
	            e.init(true, encryptionKey);
	 
	            byte[] messageBytes = inputData.getBytes();
	            byte[] hexEncodedCipher = e.processBlock(messageBytes, 0, messageBytes.length);
	 
	            
	            
	            encryptedData = getHexString(hexEncodedCipher);
	    
	        }
	        catch (Exception e) {
	            System.out.println(e);
	            e.printStackTrace();
	        }
	        
	        return encryptedData;
	    }
		
	    public String RSADecrypt (String keyFileName, String encryptedData, boolean rsaSign) {
			 
	        String outputData = null;
	        try {
	 
	            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	            String key = readFileAsString(keyFileName);
	            
	            AsymmetricKeyParameter decryptionKey;
	            if(rsaSign) {
	            	decryptionKey = (AsymmetricKeyParameter) PublicKeyFactory.createKey(Base64.decode(key));
	            } else {
	            	decryptionKey = (AsymmetricKeyParameter) PrivateKeyFactory.createKey(Base64.decode(key));
	            }
	            
	            AsymmetricBlockCipher e = new RSAEngine();
	            e = new org.bouncycastle.crypto.encodings.PKCS1Encoding(e);
	            e.init(false, decryptionKey);
	 
	            byte[] messageBytes = hexStringToByteArray(encryptedData);
	            byte[] hexEncodedCipher = e.processBlock(messageBytes, 0, messageBytes.length);
	 
	            
	            outputData = new String(hexEncodedCipher);
	 
	        }
	        catch (Exception e) {
	        	e.printStackTrace();
	            System.out.println(e);
	            return "";
	        }
	        
	        return outputData;
	    }
	    
	    public String RSAEncrypt (String inputData, boolean rsaSign){
			 
	        String encryptedData = null;
	        try {
	            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	            String key;
	            if(rsaSign) {
	            	key = readFileAsString(privKeyFilename);
	            }else {
	            	key = readFileAsString(pubKeyFilename);
	            }
	            AsymmetricKeyParameter encryptionKey;
	            if(rsaSign) {
	            	encryptionKey = (AsymmetricKeyParameter) PrivateKeyFactory.createKey(Base64.decode(key));
	            } else {
	            	encryptionKey = (AsymmetricKeyParameter) PublicKeyFactory.createKey(Base64.decode(key));
	            }
	            
	            
	            AsymmetricBlockCipher e = new RSAEngine();
	            e = new org.bouncycastle.crypto.encodings.PKCS1Encoding(e);
	            e.init(true, encryptionKey);
	 
	            byte[] messageBytes = inputData.getBytes();
	            byte[] hexEncodedCipher = e.processBlock(messageBytes, 0, messageBytes.length);
	 
	            
	            
	            encryptedData = getHexString(hexEncodedCipher);
	    
	        }
	        catch (Exception e) {
	            System.out.println(e);
	            e.printStackTrace();
	        }
	        
	        return encryptedData;
	    }
		
	    public String RSADecrypt (String encryptedData, boolean rsaSign) {
			 
	        String outputData = null;
	        try {
	 
	            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	            String key;
	            if(rsaSign) {
	            	key = readFileAsString(pubKeyFilename);
	            }else {
	            	key = readFileAsString(privKeyFilename);
	            }
	            
	            AsymmetricKeyParameter decryptionKey;
	            if(rsaSign) {
	            	decryptionKey = (AsymmetricKeyParameter) PublicKeyFactory.createKey(Base64.decode(key));
	            } else {
	            	decryptionKey = (AsymmetricKeyParameter) PrivateKeyFactory.createKey(Base64.decode(key));
	            }
	            
	            AsymmetricBlockCipher e = new RSAEngine();
	            e = new org.bouncycastle.crypto.encodings.PKCS1Encoding(e);
	            e.init(false, decryptionKey);
	 
	            byte[] messageBytes = hexStringToByteArray(encryptedData);
	            byte[] hexEncodedCipher = e.processBlock(messageBytes, 0, messageBytes.length);
	 
	            
	            outputData = new String(hexEncodedCipher);
	 
	        }
	        catch (Exception e) {
	        	e.printStackTrace();
	            System.out.println(e);
	            return "";
	        }
	        
	        return outputData;
	    }
		
		public String getHexString(byte[] b) throws Exception {
	        String result = "";
	        for (int i=0; i < b.length; i++) {
	            result +=
	                Integer.toString( ( b[i] & 0xff ) + 0x100, 16).substring( 1 );
	        }
	        return result;
	    }
		
		public byte[] hexStringToByteArray(String s) {
	        int len = s.length();
	        byte[] data = new byte[len / 2];
	        for (int i = 0; i < len; i += 2) {
	            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
	                    + Character.digit(s.charAt(i+1), 16));
	        }
	        return data;
	    }
	 
	    public String readFileAsString(String filePath) throws java.io.IOException{
	        StringBuffer fileData = new StringBuffer(1000);
	        BufferedReader reader = new BufferedReader(
	                new FileReader(filePath));
	        char[] buf = new char[1024];
	        int numRead=0;
	        while((numRead=reader.read(buf)) != -1){
	            String readData = String.valueOf(buf, 0, numRead);
	            fileData.append(readData);
	            buf = new char[1024];
	        }
	        reader.close();
	        return fileData.toString();
	    }
	    
	}
	
	class DH{
		public Key publicExp;
		private Key privateExp;
		//public Key bPublicExp;
		public KeyPairGenerator kpg;
		
		private KeyAgreement keyAgree;
		
		public DH() {
			try {
			    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
			    kpg = getKeysGenerator();
			    keyAgree = generateKeyAgreement();
			    generateExponents(kpg);
				}catch(Exception e) {
				e.printStackTrace();
			}
			
		}
		
		private KeyPairGenerator getKeysGenerator() {
			try {
			    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

			    //Define specific algorithm to use "diffie-hellman", with provider "bc"
			    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH", "BC");
			    keyGen.initialize(2048, new SecureRandom());
			    this.kpg = keyGen;
			    return keyGen;
			}catch(Exception e) {
				e.printStackTrace();
				return null;
			}
		}
		
		private KeyAgreement generateKeyAgreement() {
			try {
			    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
			    KeyAgreement keyAgree = KeyAgreement.getInstance("DH", "BC");
			    return keyAgree;
			}catch(Exception e) {
				e.printStackTrace();
				return null;
			}
		}
		private Key generateExponents(KeyPairGenerator keyGen) {
			
			try {
			    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
			    KeyPair pair = keyGen.generateKeyPair();
			    privateExp = pair.getPrivate();
			    publicExp = pair.getPublic();
			    return publicExp;
			}catch(Exception e) {
				e.printStackTrace();
				return null;
			}
		}
		public byte[] computeSharedSecret(Key bPublicExp) {
			if (bPublicExp == null) {
				System.out.println("Public Exponent argument cannot be null");
				return null;
			}
			try {
				
			    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
			    keyAgree.init(privateExp);
			    keyAgree.doPhase(bPublicExp, true);
			    return keyAgree.generateSecret();
			    
			}catch(Exception e) {
				e.printStackTrace();
				return null;
			}
		}
		
		
		
	}
	
	
}



/******************************************************************************************
 *         SAMPLE TEST FUNCTIONS FOR USAGE REFERENCE
 * ****************************************************************************************
 * 
 * public static void main(String args[]) { 
        
		Crypto crypto = new Crypto();
		AES aes = crypto.new AES();
		aes.AESTest(plaintext);
		Blowfish bf = crypto.new Blowfish();
		bf.BlowfishTest(plaintext);
		
		
		RSA myRSA = crypto.new RSA();
		myRSA.rsaTest("pubkey", "privkey", plaintext);
		
	}
 * 
 *
		
		public void rsaTest(String pubKeyName, String privKeyName, String plaintext) {
			
			
			String keynames[] = new String[2];
			keynames[0] = pubKeyName;
			keynames[1] = privKeyName;
			System.out.println("\nGenerating RSA keys and storing them in files " + pubKeyName + " and " + privKeyName);
			generateRSAKeys(keynames);
			String encryptedrsa = RSAEncrypt(pubKeyName, plaintext, false);
			System.out.println("\nRSA encrypted using " + pubKeyName + ": " + encryptedrsa);
			String decryptedrsa = RSADecrypt(privKeyName, encryptedrsa, false);
			System.out.println("\nRSA decrypted using " + privKeyName + ": " + decryptedrsa);
			String signedrsa = RSAEncrypt(privKeyName, plaintext, true);
			System.out.println("\nRSA signed (encrypted using " + privKeyName + "): " + signedrsa);
			String verifiedrsa = RSADecrypt(pubKeyName, signedrsa, true);
			System.out.println("\nRSA verified (decrypted using " + pubKeyName + "): " + verifiedrsa);
		}
		
		
		
		DH dh1 = bc.new DH();
		DH dh2 = bc.new DH();
		try {
			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

	    	MessageDigest hash = MessageDigest.getInstance("SHA1", "BC");
			System.out.println(new String(hash.digest(dh2.computeSharedSecret(dh1.aPublicExp))));
			System.out.println(new String(hash.digest(dh1.computeSharedSecret(dh2.aPublicExp))));
		}catch(Exception e) {
			e.printStackTrace();
		}
		 
 * 
 * 
 * 
 * 
 * 
 * */
