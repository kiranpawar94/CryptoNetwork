/* Implements the GroupClient Interface */

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.util.encoders.Base64;



import java.io.File;
import java.io.ObjectInputStream;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.MessageDigest;
import java.security.Security;

public class GroupClient extends Client implements GroupClientInterface {
	
	
	public String sharedSecretDH; //D-H Shared secret for the session (Symmetric key for encryption)
	public Crypto crypto;
	public Crypto.RSA RSAProvider;
    public Crypto.SHA256 DigestProvider;
    public Crypto.AES AESProvider;
    String pubKeyFileName; //RSA Public key for the curret user
	String privKeyFileName; //RSA Private key for the current user
	private boolean authenticated;
	private String currentUser;
	private boolean AESEnabled;
	
	public int clientSequence;
	public int groupSequence;
	
	public GroupClient() {
		crypto = new Crypto();
		currentUser = "";
		clientSequence = 0;
	}
	
	
	public boolean setupRSA(String username) {
		pubKeyFileName = username + "_pubkey";
		privKeyFileName = username + "_privkey";
		Crypto crypto = new Crypto();
		RSAProvider = crypto.new RSA(pubKeyFileName, privKeyFileName);
		DigestProvider = crypto.new SHA256();
		try {
			File fpub = new File(pubKeyFileName);
			File fpriv = new File(privKeyFileName);
			if (!(fpub.exists() && fpriv.exists())) {
				System.out.println("\nGenerating RSA keys and storing them in files named \""+ pubKeyFileName + "\" and \"" + privKeyFileName + "\" for the public and private keys, respectively");

				RSAProvider.generateRSAKeys();
			}
			System.out.println("\nRSA keypair found for user " + username);

			
			Envelope message = null, response = null;
 		 	
			message = new Envelope("RSA_SIGNED_PUBKEY");
			
			String key = RSAProvider.readFileAsString(pubKeyFileName);
			System.out.println("User's RSA Key: " + key);
			String keyDigest = DigestProvider.messageDigest(key);
			System.out.println("User's RSA Key Digest: " + keyDigest);
			String signedKeyDigest = RSAProvider.RSAEncrypt("pubkey", keyDigest, false);
			System.out.println("\nSending client's RSA Key encrypted digest: " + signedKeyDigest);
			
			message.addObject(key);
			message.addObject(signedKeyDigest);
			message.addObject(username);
			message.addObject(++clientSequence);
			
			output.writeObject(message);
		
			//Get the response from the server
			response = (Envelope)input.readObject();
			
			++clientSequence;
			groupSequence = (Integer)response.getObjContents().get(response.getObjContents().size() - 1);
			if(groupSequence != clientSequence) {
				//Disconnect
				System.out.println("Sequence numbers mismatch\nDisconnecting\n");
				disconnect();
			}
			
			else {
				System.out.println("Sequence numbers match\n");
			}
			
			//Successful response
			if(response.getMessage().equals("OK"))
			{		
				return true;
			} else if (response.getMessage().equals("SECURITY_ERROR_RSA")) {
				System.out.println("Client authenticaiton failed.");
			}
			return false;
		} catch(Exception e) {
			System.err.println("Error generating RSA keys for the Client: " + e.getMessage());
			e.printStackTrace(System.err);
		}
		return false;
	}
	
	
	public boolean doHandshakeDH(String username)
	 {
		try
		{
			
			Crypto.DH dhClient;
			dhClient= crypto.new DH();
			
			Envelope message = null, response = null;
		 		 	
			message = new Envelope("DH_HANDSHAKE");
			message.addObject(dhClient.publicExp);
			System.out.println("Client's DH Public Exponent: " + dhClient.publicExp.toString());
			String expDigest = DigestProvider.messageDigest(new String(dhClient.publicExp.toString()));
			System.out.println("Client's DH Public Exponent  Digest: " + expDigest);
			String signedExpDigest = RSAProvider.RSAEncrypt(expDigest, true);//SIGN WITH PRIVATE KEY
			System.out.println("\nSending client's DH Public Exponent Signed: " + signedExpDigest);
			

			message.addObject(signedExpDigest);
			message.addObject(username);
			message.addObject(++clientSequence);
			
			output.writeObject(message);
		
			//Get the response from the server
			response = (Envelope)input.readObject();
			
			++clientSequence;
			groupSequence = (Integer)response.getObjContents().get(response.getObjContents().size() - 1);
			if(groupSequence != clientSequence) {
				//Disconnect
				System.out.println("Sequence numbers mismatch\nDisconnecting\n");
				disconnect();
			}
			
			else {
				System.out.println("Sequence numbers match\n");
			}
			
			//Successful response
			if(response.getMessage().equals("OK"))
			{
				//If there is a token in the Envelope, return it 
				ArrayList<Object> temp = null;
				temp = response.getObjContents();
				
				if(temp.size() == 4)
				{
					Key serverPubExp = (Key)temp.get(0);					
					String serverPubExpDigest = DigestProvider.messageDigest(serverPubExp.toString());
					String signedServerPubExp = (String)temp.get(1);
					byte[] serverIV = (byte[])temp.get(2);
					
					
					System.out.println("Received  server's Public Exponent: " + serverPubExp.toString());
					System.out.println("Received  server's Signed Public Exponent: " + signedServerPubExp.toString());
					System.out.println("Server's Public Exponent: " + dhClient.publicExp.toString());
					//COMPARE RECEIVED CLIENT'S PUBLIC EXPONENT'S HASH WITH THE LOCALLY COMPUTED ONE
					if(verifyCompareHash("pubkey", signedServerPubExp, serverPubExpDigest)) { //Verify with server's public key
						

						try {
							Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

							MessageDigest hash = MessageDigest.getInstance("SHA256", "BC");

							String sharedSecretDH = new String(hash.digest(dhClient.computeSharedSecret(serverPubExp)));
							if(sharedSecretDH != null) {
								AESProvider = crypto.new AES(sharedSecretDH.getBytes(), serverIV);
								AESEnabled = true;
								System.out.println("\n\n\n*** SHAREDSECRET: " + sharedSecretDH);
								return true;

							}
						}catch(Exception e) {
							e.printStackTrace();
							return false;
						}
					} else {
						System.out.println("\nDiffie-Hellman Handshake failed. The public exponent received from the Server doesn't match its signature.");
					}
				}
			} else if (response.getMessage().contentEquals("SECURITY_ERROR_DH")){
				System.out.println("\nDiffie-Hellman Handshake failed. The original sent public exponent was modified during transmission.");
			}
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
		return false;
		
	 }
 
	 public UserToken getToken(String username, String fileServerName)
	 {
		 if(!(username.equals(currentUser))) {
			 authenticated = false;
			 currentUser = username;
		 }
		if(!(authenticated)) {
		 	if(!(setupRSA(username))) {
		 		
		 	
		 		return null;
		 	}
			if(doHandshakeDH(username)) {

				System.out.println("Successful Diffie-Hellman handshake, authentication can proceed");
				
			} else {

				System.out.println("Error during Diffie-Hellman handshake. Connection is not secure, can't proceed with authentication");
				return null;
			}
			authenticated  =true;
		}
		 
		 
		try
		{
			UserToken token = null;
			Envelope message = null, response = null;
		 		 	
			//Tell the server to return a token.
			message = new Envelope("GET");
			message.addObject(username); //Add user name string

			message.addObject(fileServerName); // Add file server name string

			message.addObject(++clientSequence);
			

			if (AESEnabled) {
				Envelope encryptedEnvelope = EnvelopeEncryptionUtil.encryptEnvelope(message, AESProvider);
				output.writeObject(encryptedEnvelope);
			} else {
				output.writeObject(message);
			}
		
			//Get the response from the server
			response = (Envelope)input.readObject();
			if (AESEnabled) {
				response  = EnvelopeEncryptionUtil.decryptEnvelope(response, AESProvider);
				if (response == null) {
					System.out.println("*** Null Envelope");
					
				}
			}
			
			++clientSequence;
			groupSequence = (Integer)response.getObjContents().get(response.getObjContents().size() - 1);
			if(groupSequence != clientSequence) {
				//Disconnect
				System.out.println("Sequence numbers mismatch\nDisconnecting\n");
				disconnect();
			}
			
			else {
				System.out.println("Sequence numbers match\n");
			}
			
			//Successful response
			if(response.getMessage().equals("OK"))
			{
				//If there is a token in the Envelope, return it 
				ArrayList<Object> temp = null;
				temp = response.getObjContents();
				
				if(temp.size() == 2)
				{
					token = (UserToken)temp.get(0);
					return token;
				}
			}else {
				System.out.println("Token request failed\n");
			}
			
			return null;
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return null;
		}
		
	 }
	 
	 public boolean createUser(String username, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to create a user
				message = new Envelope("CUSER");
				message.addObject(username); //Add user name string
				message.addObject(token); //Add the requester's token
				message.addObject(++clientSequence);
				
				if (AESEnabled) {
					Envelope encryptedEnvelope = EnvelopeEncryptionUtil.encryptEnvelope(message, AESProvider);
					output.writeObject(encryptedEnvelope);
				} else {
					output.writeObject(message);
				}
			
				response = (Envelope)input.readObject();
				if (AESEnabled) {
					response = EnvelopeEncryptionUtil.decryptEnvelope(response, AESProvider);
					if (response == null) {
						System.out.println("*** Null Envelope");
					}
				}
				
				++clientSequence;
				groupSequence = (Integer)response.getObjContents().get(response.getObjContents().size() - 1);
				if(groupSequence != clientSequence) {
					//Disconnect
					System.out.println("Sequence numbers mismatch\nDisconnecting\n");
					disconnect();
				}
				
				else {
					System.out.println("Sequence numbers match\n");
				}
				
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				}
				
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }
	 
	 public boolean deleteUser(String username, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
			 
				//Tell the server to delete a user
				message = new Envelope("DUSER");
				message.addObject(username); //Add user name
				message.addObject(token);  //Add requester's token
				message.addObject(++clientSequence);
				
				if (AESEnabled) {
					Envelope encryptedEnvelope = EnvelopeEncryptionUtil.encryptEnvelope(message, AESProvider);
					output.writeObject(encryptedEnvelope);
				} else {
					output.writeObject(message);
				}
			
				response = (Envelope)input.readObject();
				if (AESEnabled) {
					response  = EnvelopeEncryptionUtil.decryptEnvelope(response, AESProvider);
					if (response == null) {
						System.out.println("*** Null Envelope");
						
					}
				}
				
				++clientSequence;
				groupSequence = (Integer)response.getObjContents().get(response.getObjContents().size() - 1);
				if(groupSequence != clientSequence) {
					//Disconnect
					System.out.println("Sequence numbers mismatch\nDisconnecting\n");
					disconnect();
				}
				
				else {
					System.out.println("Sequence numbers match\n");
				}
				
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				}
				
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }
	 
	 public boolean createGroup(String groupname, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to create a group
				message = new Envelope("CGROUP");
				message.addObject(groupname); //Add the group name string
				message.addObject(token); //Add the requester's token
				message.addObject(++clientSequence);
				
				if (AESEnabled) {
					Envelope encryptedEnvelope = EnvelopeEncryptionUtil.encryptEnvelope(message, AESProvider);
					output.writeObject(encryptedEnvelope);
				} else {
					output.writeObject(message);
				}
			
				response = (Envelope)input.readObject();
				if (AESEnabled) {
					response  = EnvelopeEncryptionUtil.decryptEnvelope(response, AESProvider);
					if (response == null) {
						System.out.println("*** Null Envelope");
						
					}
				}
				
				++clientSequence;
				groupSequence = (Integer)response.getObjContents().get(response.getObjContents().size() - 1);
				if(groupSequence != clientSequence) {
					//Disconnect
					System.out.println("Sequence numbers mismatch\nDisconnecting\n");
					disconnect();
				}
				
				else {
					System.out.println("Sequence numbers match\n");
				}
				
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				}
				
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }
	 
	 public boolean deleteGroup(String groupname, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to delete a group
				message = new Envelope("DGROUP");
				message.addObject(groupname); //Add group name string
				message.addObject(token); //Add requester's token
				message.addObject(++clientSequence);
				
				if (AESEnabled) {
					Envelope encryptedEnvelope = EnvelopeEncryptionUtil.encryptEnvelope(message, AESProvider);
					output.writeObject(encryptedEnvelope);
				} else {
					output.writeObject(message);
				}
			
				response = (Envelope)input.readObject();
				if (AESEnabled) {
					response  = EnvelopeEncryptionUtil.decryptEnvelope(response, AESProvider);
					if (response == null) {
						System.out.println("*** Null Envelope");
						
					}
				}
				
				++clientSequence;
				groupSequence = (Integer)response.getObjContents().get(response.getObjContents().size() - 1);
				if(groupSequence != clientSequence) {
					//Disconnect
					System.out.println("Sequence numbers mismatch\nDisconnecting\n");
					disconnect();
				}
				
				else {
					System.out.println("Sequence numbers match\n");
				}
				
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				}
				
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }
	 
	 @SuppressWarnings("unchecked")
	public List<String> listMembers(String group, UserToken token)
	 {
		 try
		 {
			 Envelope message = null, response = null;
			 //Tell the server to return the member list
			 message = new Envelope("LMEMBERS");
			 message.addObject(group); //Add group name string
			 message.addObject(token); //Add requester's token
			 message.addObject(++clientSequence);
			 
			 if (AESEnabled) {
					Envelope encryptedEnvelope = EnvelopeEncryptionUtil.encryptEnvelope(message, AESProvider);
					output.writeObject(encryptedEnvelope);
				} else {
					output.writeObject(message);
				}
			 
			 
			 response = (Envelope)input.readObject();
			 if (AESEnabled) {
					response = EnvelopeEncryptionUtil.decryptEnvelope(response, AESProvider);
					if (response == null) {
						System.out.println("*** Null Envelope");
					}
				}
			 
				++clientSequence;
				groupSequence = (Integer)response.getObjContents().get(response.getObjContents().size() - 1);
				if(groupSequence != clientSequence) {
					//Disconnect
					System.out.println("Sequence numbers mismatch\nDisconnecting\n");
					disconnect();
				}
				
				else {
					System.out.println("Sequence numbers match\n");
				}
				
			 System.out.println(response.getMessage());
			 
			 //If server indicates success, return the member list
			 if(response.getMessage().equals("OK"))
			 { 
				return (List<String>)response.getObjContents().get(0); //This cast creates compiler warnings. Sorry.
			 }
				
			 return null;
			 
		 }
		 catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return null;
			}
	 }
	 
	 public boolean addUserToGroup(String username, String groupname, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to add a user to the group
				message = new Envelope("AUSERTOGROUP");
				message.addObject(username); //Add user name string
				message.addObject(groupname); //Add group name string
				message.addObject(token); //Add requester's token
				message.addObject(++clientSequence);
				
				if (AESEnabled) {
					Envelope encryptedEnvelope = EnvelopeEncryptionUtil.encryptEnvelope(message, AESProvider);
					output.writeObject(encryptedEnvelope);
				} else {
					output.writeObject(message);
				}
			
				response = (Envelope)input.readObject();
				if (AESEnabled) {
					response = EnvelopeEncryptionUtil.decryptEnvelope(response, AESProvider);
					if (response == null) {
						System.out.println("*** Null Envelope");
					}
				}
				
				++clientSequence;
				groupSequence = (Integer)response.getObjContents().get(response.getObjContents().size() - 1);
				if(groupSequence != clientSequence) {
					//Disconnect
					System.out.println("Sequence numbers mismatch\nDisconnecting\n");
					disconnect();
				}
				
				else {
					System.out.println("Sequence numbers match\n");
				}
				
				//If server indicates success, return true
				if(response.getMessage().equals("OK"))
				{
					return true;
				}
				
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }
	 
	 public boolean deleteUserFromGroup(String username, String groupname, UserToken token)
	 {
		 try
			{
				Envelope message = null, response = null;
				//Tell the server to remove a user from the group
				message = new Envelope("RUSERFROMGROUP");
				message.addObject(username); //Add user name string
				message.addObject(groupname); //Add group name string
				message.addObject(token); //Add requester's token
				message.addObject(++clientSequence);
				
				if (AESEnabled) {
					Envelope encryptedEnvelope = EnvelopeEncryptionUtil.encryptEnvelope(message, AESProvider);
					output.writeObject(encryptedEnvelope);
				} else {
					output.writeObject(message);
				}			
				response = (Envelope)input.readObject();
				if (AESEnabled) {
					response = EnvelopeEncryptionUtil.decryptEnvelope(response, AESProvider);
					if (response == null) {
						System.out.println("*** Null Envelope");
					}
				}
				//If server indicates success, return true
				++clientSequence;
				groupSequence = (Integer)response.getObjContents().get(response.getObjContents().size() - 1);
				if(groupSequence != clientSequence) {
					//Disconnect
					System.out.println("Sequence numbers mismatch\nDisconnecting\n");
					disconnect();
				}
				
				else {
					System.out.println("Sequence numbers match\n");
				}
				
				if(response.getMessage().equals("OK"))
				{
					return true;
				}
				
				return false;
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return false;
			}
	 }
	 
	 public boolean verifyCompareHash(String pubKeyFileName, String encryptedHash, String computedHash) {
			System.out.println("\nReceived plaintext's digest: " + computedHash);

			System.out.println("\nReceived encrypted plaintext's digest: " + encryptedHash);
			
			String decryptedHash = RSAProvider.RSADecrypt(pubKeyFileName, encryptedHash, true);//verify with client's public key
			System.out.println("\nReceived decrypted plaintext's digest: " + decryptedHash);
			if(computedHash.contentEquals(decryptedHash)) {
				System.out.println("\nData integrity verified: Plaintext's digest matches the received digest verified");
				return true;
			}
				return false;
		}
	

}