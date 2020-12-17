/* This thread does all the work. It communicates with the client through Envelopes.
 * 
 */
import java.lang.Thread;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.MessageDigest;
import java.security.Security;
import java.io.*;
import java.util.*;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.util.encoders.Base64;


public class GroupThread extends Thread 
{
	private boolean AESEnabled;
	private final Socket socket;
	private GroupServer my_gs;
	public String sharedSecretDH;
	
	public int clientSequence;
	public int groupSequence;
	
	public GroupThread(Socket _socket, GroupServer _gs)
	{
		socket = _socket;
		my_gs = _gs;
		
		
	
	}
	
	public void run()
	{
		groupSequence = 0;
		boolean proceed = true;

		try
		{
			//Announces connection and opens object streams
			System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
			final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
			final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
			
			do
			{
				Envelope message = (Envelope)input.readObject();
				
				if (AESEnabled) {
					message = EnvelopeEncryptionUtil.decryptEnvelope(message, my_gs.AESProvider);
					if (message == null) {
						System.out.println("*** Null Envelope");
						continue;
					}
				}
				
				++groupSequence;
				clientSequence = (Integer)message.getObjContents().get(message.getObjContents().size()-1);
				if(clientSequence != groupSequence) {
					//Disconnect
					System.out.println("Sequence numbers mismatch\nDisconnecting\n");
				}
				
				else {
					System.out.println("Sequence numbers match");
				}
				
				System.out.println("Request received: " + message.getMessage());
				Envelope response;
				
				if(message.getMessage().equals("GET"))//Client wants a token
				{
					if(message.getObjContents().size() < 3)
					{
						response = new Envelope("FAIL");
						response.addObject(null);
						response.addObject(++groupSequence);
					}
					else
					{
						String username = (String)message.getObjContents().get(0); //Get the username
						String fileServerName = (String)message.getObjContents().get(1); // Get the file server name
						if (username == null || fileServerName == null) {
							response = new Envelope("FAIL");
							response.addObject(null);
							response.addObject(++groupSequence);
						}
						else {
							UserToken yourToken = createToken(username, fileServerName); //Create a token
							response = new Envelope("OK");
							response.addObject(yourToken);
							response.addObject(++groupSequence);
						}
					}
					if (AESEnabled) {
						Envelope encryptedEnvelope = EnvelopeEncryptionUtil.encryptEnvelope(response, my_gs.AESProvider);
						output.writeObject(encryptedEnvelope);
					} else {
						output.writeObject(response);
					}					
				}
				else if(message.getMessage().equals("CUSER")) //Client wants to create a user
					
				{
					
					if(message.getObjContents().size() < 3)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						
						response = new Envelope("FAIL");
						
						if(message.getObjContents().get(0) != null)
							
						{
							if(message.getObjContents().get(1) != null)
							{
							
								String username = (String)message.getObjContents().get(0); //Extract the username
								UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token
								if(!(checkToken(yourToken))) {
									System.out.println("Operation failed, forged token detected");
									response = new Envelope("FAIL"); //Success
								}else {
									if(createUser(username, yourToken))
									{
										response = new Envelope("OK"); //Success
									}
								}
							}
						}
					}
					response.addObject(++groupSequence);
					if (AESEnabled) {
						Envelope encryptedEnvelope = EnvelopeEncryptionUtil.encryptEnvelope(response, my_gs.AESProvider);
						output.writeObject(encryptedEnvelope);
					} else {
						output.writeObject(response);
					}
				}
				else if(message.getMessage().equals("DUSER")) //Client wants to delete a user
				{
					
					if(message.getObjContents().size() < 3)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");
						
						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								String username = (String)message.getObjContents().get(0); //Extract the username
								UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token
								if(!(checkToken(yourToken))) {
									System.out.println("Operation failed, forged token detected");
									response = new Envelope("FAIL"); //Success
								}else {
									if(deleteUser(username, yourToken))
									{
										response = new Envelope("OK"); //Success
									}
								}
							}
						}
					}
					response.addObject(++groupSequence);
					if (AESEnabled) {
						Envelope encryptedEnvelope = EnvelopeEncryptionUtil.encryptEnvelope(response, my_gs.AESProvider);
						output.writeObject(encryptedEnvelope);
					} else {
						output.writeObject(response);
					}
				}
				else if(message.getMessage().equals("CGROUP")) //Client wants to create a group
				{
					if(message.getObjContents().size() < 3)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");
						
						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{

								String groupname = (String)message.getObjContents().get(0); //Extract the groupname

								UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token
								if(!(checkToken(yourToken))) {
									System.out.println("Operation failed, forged token detected");
									response = new Envelope("FAIL"); //Success
								}else {
									if(createGroup(groupname, yourToken))
									{
										response = new Envelope("OK"); //Success
									}
								}
							}
						}
					}
					
					response.addObject(++groupSequence);
					
					if (AESEnabled) {
						Envelope encryptedEnvelope = EnvelopeEncryptionUtil.encryptEnvelope(response, my_gs.AESProvider);
						output.writeObject(encryptedEnvelope);
					} else {
						output.writeObject(response);
					}

				}
				else if(message.getMessage().equals("DGROUP")) //Client wants to delete a group
				{
				    /* TODO:  Write this handler */
					if(message.getObjContents().size() < 3)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");
						
						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								String groupname = (String)message.getObjContents().get(0); //Extract the username
								UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token
								if(!(checkToken(yourToken))) {
									System.out.println("Operation failed, forged token detected");
									response = new Envelope("FAIL"); //Success
								}else {
									if(deleteGroup(groupname, yourToken))
									{
										response = new Envelope("OK"); //Success
									}
								}
							}
								
						}
					}
					
					response.addObject(++groupSequence);
					if (AESEnabled) {
						Envelope encryptedEnvelope = EnvelopeEncryptionUtil.encryptEnvelope(response, my_gs.AESProvider);
						output.writeObject(encryptedEnvelope);
					} else {
						output.writeObject(response);
					}				}
				else if(message.getMessage().equals("LMEMBERS")) //Client wants a list of members in a group
				{
					if(message.getObjContents().size() < 3)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");
						
						if(message.getObjContents().get(0) != null)
						{
							if(message.getObjContents().get(1) != null)
							{
								String groupname = (String)message.getObjContents().get(0); //Extract the grouop name
								UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token
								if(!(checkToken(yourToken))) {
									System.out.println("Operation failed, forged token detected");
									response = new Envelope("FAIL"); //Success
								}else {
									ArrayList<String> groupUserList = listMembers(groupname, yourToken);
									ArrayList<String> tdb = new ArrayList<String>();
									if( groupUserList != null)
									{
										for (int i = 0; i < groupUserList.size(); i++) {
											tdb.add(groupUserList.get(i));
										}
										System.out.println("OK");
										response = new Envelope("OK"); //Success
										response.addObject(tdb);
									} else {
										response = new Envelope("No permission. Access denied. ");
									}
								}
							}
						}
					}
					
					response.addObject(++groupSequence);
					
					if (AESEnabled) {
						Envelope encryptedEnvelope = EnvelopeEncryptionUtil.encryptEnvelope(response, my_gs.AESProvider);
						output.writeObject(encryptedEnvelope);
					} else {
						output.writeObject(response);
					}				}
				else if(message.getMessage().equals("AUSERTOGROUP")) //Client wants to add user to a group
				{

					if(message.getObjContents().size() < 4)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");
						
						if(message.getObjContents().get(0) != null && (message.getObjContents().get(1) != null) && (message.getObjContents().get(2) != null)) {
							
								String username = (String)message.getObjContents().get(0);
								String groupname = (String)message.getObjContents().get(1);
								UserToken yourToken = (UserToken)message.getObjContents().get(2);
								if(!(checkToken(yourToken))) {
									System.out.println("Operation failed, forged token detected");
									response = new Envelope("FAIL"); //Success
								}else {
								if( addUserToGroup(username, groupname, yourToken))
								{
									response = new Envelope("OK"); //Success
								}
							}
							
						}
					}
					
					response.addObject(++groupSequence);
					
					if (AESEnabled) {
						Envelope encryptedEnvelope = EnvelopeEncryptionUtil.encryptEnvelope(response, my_gs.AESProvider);
						output.writeObject(encryptedEnvelope);
					} else {
						output.writeObject(response);
					}
				}
				else if(message.getMessage().equals("RUSERFROMGROUP")) //Client wants to remove user from a group
				{
					if(message.getObjContents().size() < 4)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");
						
						if(message.getObjContents().get(0) != null && (message.getObjContents().get(1) != null) && (message.getObjContents().get(2) != null)) {
							
							String username = (String)message.getObjContents().get(0);
							String groupname = (String)message.getObjContents().get(1);
							UserToken yourToken = (UserToken)message.getObjContents().get(2);
							if(!(checkToken(yourToken))) {
								System.out.println("Operation failed, forged token detected");
								response = new Envelope("FAIL"); //Success
							}else {
								if( removeUserFromGroup(username, groupname, yourToken))
								{
									response = new Envelope("OK"); //Success
								}
							}
						}
					}
					
					response.addObject(++groupSequence);
					
					if (AESEnabled) {
						Envelope encryptedEnvelope = EnvelopeEncryptionUtil.encryptEnvelope(response, my_gs.AESProvider);
						output.writeObject(encryptedEnvelope);
					} else {
						output.writeObject(response);
					}					
				}else if(message.getMessage().equals("DISCONNECT")) //Client wants to disconnect
				{
					socket.close(); //Close the socket
					proceed = false; //End this communication loop
				}else if(message.getMessage().equals("DH_HANDSHAKE")) //Client sends his public exponent for DH
				{
					if(message.getObjContents().size() < 3)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");
						
						if(message.getObjContents().get(0) != null && message.getObjContents().get(1) != null&& message.getObjContents().get(2) != null) {
								
								Crypto crypto = new Crypto();
								Crypto.DH dhServer;
								dhServer= crypto.new DH();
								
								Key clientPubExp = (Key)message.getObjContents().get(0);
								String clientPubExpDigest = my_gs.DigestProvider.messageDigest(clientPubExp.toString());
								String signedClientPubExp = (String)message.getObjContents().get(1);
								String username = (String)message.getObjContents().get(2);
								
								System.out.println("Received " + username + "'s Public Exponent: " + clientPubExp.toString());
								System.out.println("Received " + username + "'s Public Exponent's digest: " + clientPubExpDigest);

								System.out.println("Received " + username + "'s Signed Public Exponent: " + signedClientPubExp.toString());
								
								//COMPARE RECEIVED CLIENT'S PUBLIC EXPONENT'S HASH WITH THE LOCALLY COMPUTED ONE
								if(verifyCompareHash("." + File.separator + "users_pubkeys" + File.separator + username + "_pubkey", signedClientPubExp, clientPubExpDigest)) {
									
								
									try {
										Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
										// 	Generate a 256-bit key out of the shared secret
										MessageDigest hash = MessageDigest.getInstance("SHA256", "BC");

										sharedSecretDH = new String(hash.digest(dhServer.computeSharedSecret(clientPubExp)));

										if(sharedSecretDH != null) {
											byte[] serverIV = crypto.generateRandomBytes(16);
											my_gs.AESProvider = crypto.new AES(sharedSecretDH.getBytes(), serverIV);
											AESEnabled = true;
											
											response = new Envelope("OK");
											
											System.out.println("Server's Public Exponent: " + dhServer.publicExp.toString());
											String expDigest = my_gs.DigestProvider.messageDigest(new String(dhServer.publicExp.toString()));
											System.out.println("Server's DH Public Exponent  Digest: " + expDigest);
											String signedExpDigest = my_gs.RSAProvider.RSAEncrypt(expDigest, true);//SIGN WITH PRIVATE KEY
											System.out.println("\nSending Server's DH Public Exponent Signed: " + signedExpDigest);
											
											response.addObject(dhServer.publicExp);
											response.addObject(signedExpDigest);
											response.addObject(serverIV);
											System.out.println("\n\n\n*** SHAREDSECRET: " + sharedSecretDH);
										}
									}catch(Exception e) {
										e.printStackTrace();
									}
								} else {
									System.out.println("Diffie-Hellman handshake failed. The Client's Public Exponent Digest doesn't match it's signature. There might be a MITM");
									response = new Envelope("SECURITY_ERROR_DH");
								}
								
						}
					}
					
						response.addObject(++groupSequence);
						output.writeObject(response);
								
				}
				else if(message.getMessage().equals("RSA_SIGNED_PUBKEY")) //Client sends his public RSA key 
				{
					if(message.getObjContents().size() != 4)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");
						
						if(message.getObjContents().get(0) != null && message.getObjContents().get(1) != null && message.getObjContents().get(2) != null) {
							
							String clientPubKey = (String)message.getObjContents().get(0);
							String clientPubKeyDigest = my_gs.DigestProvider.messageDigest(clientPubKey);
							String clientPubKeyDigestEncrypted = (String)message.getObjContents().get(1);
							String username = (String)message.getObjContents().get(2);
							if (my_gs.userList.checkUser(username)) {
							/*//// COMPUTE MESSAGE AND COMPARE WITH THE DECRYPTED ONE
							System.out.println("\nReceived client's RSA Key: " + clientPubKey);
							System.out.println("\nReceived encrypted client's RSA Key Digest: " + clientPubKeyDigestEncrypted);
							
						
							String clientPubKeyDigestDecrypted = my_gs.RSAProvider.RSADecrypt(clientPubKeyDigestEncrypted, false);//decrypt with server's private key
							System.out.println("\nReceived and Decrypted client's RSA Key Digest: " + clientPubKeyDigestDecrypted);
							if(clientPubKeyDigest.contentEquals(clientPubKeyDigestDecrypted)) {*/
							if(decryptCompareHash(clientPubKeyDigestEncrypted, clientPubKeyDigest)) {
								System.out.println("\nData integrity verified for client's public key ");
								
							//// COMPARE PROVIDED PUBLIC KEY WITH STORED ONE, OR STORE IF IT'S FROM A NEW USER
								File tmpDir = new File("." + File.separator + "users_pubkeys");
								
								//CHECK DIRECTORY EXISTS
								if(tmpDir.exists() && tmpDir.isDirectory()) {
									System.out.println("\n\n\t/users_pubkeys found");
									//CHECK IF USER'S PUBLIC KEY  IS ALREADY STORED
									File tmpFile = new File("." + File.separator + "users_pubkeys" + File.separator + username + "_pubkey");
									if(tmpFile.exists() && tmpFile.isFile()) {

										System.out.println("\n\n\t/admin_pubkeydigest found");
										//READ PUBLIC KEY FROM DISK
										String storedPubKey = my_gs.RSAProvider.readFileAsString("." + File.separator + "users_pubkeys" + File.separator + username + "_pubkey");
										//COMPARE WITH RECEIVED KEY 
										if(storedPubKey.contentEquals(clientPubKey)) {

											System.out.println("\n\n\t/admin_pubkey matches");
											response = new Envelope("OK");
										} else {
											response = new Envelope("SECURITY_ERROR_RSA");
											System.out.println("\n*** SECURITY ERROR: Client's key's digest doesn't match its digest stored in the server. Client Should check with the system admin if this is an error.");
										}
										
									}else { // NEW USER
										//STORE KEY DIGEST
										if(storeClientPubKey(username, clientPubKey)) {

											System.out.println("\n\n\t/admin_pubkey stored");
											//OK
											response = new Envelope("OK");
										}
										
									}
								}else {
									//FIRST USER EVER IN SERVER -> CREATE DIRECTORY AND STORE PUBLIC KEY
									if(tmpDir.mkdir()) {
										if(storeClientPubKey(username, clientPubKey)) {

											System.out.println("\n\n\t/admin_pubkey stored");
											//OK
											response = new Envelope("OK");
										}
										
									}else {
										response = new Envelope("SECURITY_ERROR_RSA");
										System.out.println("\nError encountered while creating the directory ./users_pubkeys. Please, check the current working directory");
									}
								}
								
							}else {
								response = new Envelope("SECURITY_ERROR_RSA");

								System.out.println("\n*** SECURITY ERROR: Received key's digest doesn't match the decrypted digest. Data integrity might have been compromised during the communication.");
							}
							//byte[] clientPubKeyBytes = clientPubKey.getBytes(StandardCharsets.UTF_8);		
						} else {
							System.out.println("Token request received for nonexistent user. Response to client is just FAIL, so no further information can be gathered in case of an attack");
						}
					}
				}
					
					response.addObject(++groupSequence);
					
					if (AESEnabled) {
						Envelope encryptedEnvelope = EnvelopeEncryptionUtil.encryptEnvelope(response, my_gs.AESProvider);
						output.writeObject(encryptedEnvelope);
					} else {
						output.writeObject(response);
					}				}
				else
				{
					response = new Envelope("FAIL"); //Server does not understand client request
					response.addObject(++groupSequence);
					output.writeObject(response);
				}
			}while(proceed);	
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
	
	
	//Method to create tokens
	private UserToken createToken(String username, String fileServerName) 
	{
		//Check that user exists
		if(my_gs.userList.checkUser(username))
		{
			ArrayList<String> userGroupList = my_gs.userList.getUserGroups(username);
			ArrayList<String> groupKeys = new ArrayList<String>();
			ArrayList<String> g_ = new ArrayList<String>();
			for (int i = 0; i < userGroupList.size(); i++) {
				String groupName = userGroupList.get(i);
				g_.add(groupName);
				groupKeys.add(my_gs.groupList.getGroupKey(groupName));
			}
			//Issue a new token with server's name and user's name
			String hash = my_gs.DigestProvider.messageDigest(my_gs.name + username + fileServerName);
			String signature = my_gs.RSAProvider.RSAEncrypt(hash, true); // RSA Sign = true -> Encrypt with private key
			String verifiedOriginal = my_gs.RSAProvider.RSADecrypt(signature, true);

			UserToken yourToken = new Token(my_gs.name, username, g_, groupKeys, signature, fileServerName);
			return yourToken;
		}
		else
		{
			return null;
		}
	}
	
	
	//Method to create a user
	private boolean createUser(String username, UserToken yourToken)
	{
		String requester = yourToken.getSubject();
		
		//Check if requester exists
		if(my_gs.userList.checkUser(requester))
		{
			//Get the user's groups
			ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
			//requester needs to be an administrator
			if(temp.contains("ADMIN"))
			{
				//Does user already exist?
				if(my_gs.userList.checkUser(username))
				{
					return false; //User already exists
				}
				else
				{
					my_gs.userList.addUser(username);
					return true;
				}
			}
			else
			{
				return false; //requester not an administrator
			}
		}
		else
		{
			return false; //requester does not exist
		}
	}
	
	//Method to delete a user
	private boolean deleteUser(String username, UserToken yourToken)
	{
		String requester = yourToken.getSubject();
		Token t = (Token)yourToken;
		String fileServerName = t.getFileServerName();
		
		//Does requester exist?
		if(my_gs.userList.checkUser(requester))
		{
			ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
			//requester needs to be an administer
			if(temp.contains("ADMIN"))
			{
				//Does user exist?
				if(my_gs.userList.checkUser(username))
				{
					//User needs deleted from the groups they belong
					ArrayList<String> deleteFromGroups = new ArrayList<String>();
					//This will produce a hard copy of the list of groups this user belongs
					for(int index = 0; index < my_gs.userList.getUserGroups(username).size(); index++)
					{
						deleteFromGroups.add(my_gs.userList.getUserGroups(username).get(index));
						// remove the deleted user from the group
						my_gs.groupList.removeUser(my_gs.userList.getUserGroups(username).get(index), username);
					}
					
					//If groups are owned, they must be deleted
					ArrayList<String> deleteOwnedGroup = new ArrayList<String>();
					
					//Make a hard copy of the user's ownership list
					for(int index = 0; index < my_gs.userList.getUserOwnership(username).size(); index++)
					{
						deleteOwnedGroup.add(my_gs.userList.getUserOwnership(username).get(index));
					}
					
					
					//Delete owned groups
					for(int index = 0; index < deleteOwnedGroup.size(); index++)
					{
						//Use the delete group method. Token must be created for this action
						String hash = my_gs.DigestProvider.messageDigest(my_gs.name + username + fileServerName);
						String signature = my_gs.RSAProvider.RSAEncrypt(hash, true); // RSA Sign = true -> Encrypt with private key
						
						deleteGroup(deleteOwnedGroup.get(index), new Token(my_gs.name, username, deleteOwnedGroup, new ArrayList<String>(), signature, fileServerName));
					}
					
					//Delete the user from the user list
					my_gs.userList.deleteUser(username);
					
					return true;	
				}
				else
				{
					return false; //User does not exist
					
				}
			}
			else
			{
				return false; //requester is not an administer
			}
		}
		else
		{
			return false; //requester does not exist
		}
	}
	

	//Method to create a group
	private boolean createGroup(String groupname, UserToken yourToken)
	{
		String requester = yourToken.getSubject();
		
		//Check if requester exists
		if(my_gs.userList.checkUser(requester))
		{
			if (my_gs.userList.getUserGroups(requester).contains("ADMIN")) {
				//Get the user's groups
				ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
			// 	Does group already exist? 
				if(my_gs.userList.checkGroup(groupname)) {
					return false; //Group already exists
				}
				else {
					// add group to the group list
					my_gs.groupList.addGroup(groupname);
					// add requester to the owner of the created group 
					my_gs.groupList.addOwner(groupname, requester);
					// update user's group and ownership
					my_gs.userList.addGroup(requester, groupname);
					my_gs.userList.addOwnership(requester, groupname);
					return true;
				}
			}else {
				return false; //requester not authorized
			}
		}
		else
		{
			return false; //requester does not exist
		}
	}

	//Method to delete a group
	//Note: only one owner's action is required
	private boolean deleteGroup(String groupname, UserToken yourToken) {
		
		String requester = yourToken.getSubject();
		
		//Does requester exist?
		if(my_gs.userList.checkUser(requester))
		{
			ArrayList<String> temp = my_gs.userList.getUserOwnership(requester);
			//requester needs to be an owner
			if(temp.contains(groupname))
			{
				// get a list of users and owners of this group
				ArrayList<String> gu = my_gs.groupList.listGroupUsers(groupname);
				ArrayList<String> go = my_gs.groupList.listGroupOwners(groupname);
				// iterate through these users and removeGroup and removeOwnership
				
				for (int index = 0; index < gu.size(); index++) {
					my_gs.userList.removeGroup(gu.get(index), groupname);
				}
				for (int index = 0; index < go.size(); index++) {
					my_gs.userList.removeOwnership(go.get(index), groupname);
				}
				// delete the group from the group list
				my_gs.groupList.deleteGroup(groupname);					
				return true;	
			}
			else
			{
				return false; //requester is not an owner
			}
		}
		else
		{
			return false; //requester does not exist
		}
	}
	
	private ArrayList<String> listMembers(String groupname, UserToken yourToken){
		String requester = yourToken.getSubject();
		//Check if requester exists
		if(my_gs.userList.checkUser(requester)){
			if(my_gs.groupList.listGroups().contains(groupname)) {

				System.out.println("Group exists");
				//Get the user's groups
				ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
			
			//	requester needs to be an administrator
			
				if(temp.contains("ADMIN") || (my_gs.groupList.listGroupOwners(groupname).contains(requester))){
					return my_gs.groupList.listGroupUsers(groupname);
				} else {
					System.out.println("Access denied");
					return null; // requester does not have permissions
				}
			}else {
				return null; //group doesn't exist
			}
			
		} else {
			
			return null; //requester does not exist
		}
	}
	
	private boolean addUserToGroup(String username, String groupname, UserToken yourToken) {
		String requester = yourToken.getSubject();
		//Check if requester exists
		if(my_gs.userList.checkUser(requester)){
			//Get the user's groups
			ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
			if(my_gs.groupList.listGroups().contains(groupname)) {
			//requester needs to be an administrator
				if(temp.contains("ADMIN") || (my_gs.groupList.listGroupOwners(groupname).contains(requester))){
					if (my_gs.userList.getUserList().contains(username)) {

						System.out.println(my_gs.userList.getUserGroups(username).toString());
						System.out.println(my_gs.groupList.listGroups());
						System.out.println(my_gs.groupList.listGroupUsers(groupname));
						System.out.println("\n*******************\n Adding user " + username + " to group " + groupname);
						if(!(my_gs.groupList.listGroupUsers(groupname).contains(username))) {
						my_gs.userList.addGroup(username, groupname);
						my_gs.groupList.addUser(username, groupname);
						}else {
							System.out.println("User already in group");
							return false; // user does not exist
						}
						System.out.println(my_gs.userList.getUserGroups(username).toString());
						System.out.println(my_gs.groupList.listGroups());
						System.out.println(my_gs.groupList.listGroupUsers(groupname));
						return true;
					}else {
						System.out.println("User doesn't exist");
						return false; // user does not exist
					}
				} else {
					System.out.println("Requester hasn't permissions");

					return false; // requester does not have permissions
				}
			}else {				
				System.out.println("Group doesn't exist");
				return false; // group doesn't exist
			}
			
		} else {
			System.out.println("requester doesn't exist");
			return false; //requester does not exist
		}
	}
	
	private boolean removeUserFromGroup(String username, String groupname, UserToken yourToken){
		
		String requester = yourToken.getSubject();
		
		//Check if requester exists
		if(my_gs.userList.checkUser(requester)){
			
			//Get the user's groups
			ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
			
			if(my_gs.groupList.listGroups().contains(groupname)) {
				
			
			//requester needs to be an administrator
				if(temp.contains("ADMIN") || (my_gs.groupList.listGroupOwners(groupname).contains(requester))){
					
				
					if (my_gs.userList.getUserList().contains(username)) {
						
					
						if(my_gs.userList.getUserGroups(requester).contains(groupname)){
							my_gs.userList.removeGroup(username, groupname);
							my_gs.groupList.removeUser(groupname, username);
							if(my_gs.userList.getUserOwnership(username).contains(groupname)) {
								my_gs.userList.removeOwnership(username, groupname);
								my_gs.groupList.removeOwner(groupname, username);
							}
							return true;
						}else {
							return false; // user is not in group
						
						}
		
					}else {
						return false; // user does not exist
					}
				} else {
					return false; // requester does not have permissions
				}
			}else {
				return false; // group doesn't exist
			}
			
		} else {
			return false; //requester does not exist
		}
		
	}
	
	public boolean checkToken(UserToken yourToken) {
		Token t = (Token)yourToken;
		String plaintext = t.getIssuer() + t.getSubject() + t.getFileServerName();

		String hash = my_gs.DigestProvider.messageDigest(plaintext);

		
		String verified = my_gs.RSAProvider.RSADecrypt(t.getSignature(), true);

		if (verified.equals(hash)) {
			System.out.println("Token's digest matches the digest signed by the Server. Verification successful");

			return true;
		}
		else {
			return false;
		}
	}
	
	public boolean storeClientPubKey(String username, String clientPubKey) {
		try {
			File tmpFile = new File("." + File.separator + "users_pubkeys" + File.separator + username + "_pubkey");
			if(tmpFile.createNewFile()) {
				FileWriter myWriter = new FileWriter("." + File.separator + "users_pubkeys" + File.separator + username + "_pubkey");
				myWriter.write(clientPubKey);
				myWriter.close();	
				System.out.println("Successfully stored " + username + "'s public key");
				return true;
			}else {
				System.out.println("Error encountered while creating the file ./users_pubkeys/" + username + "_pubkey . Please, check the current working directory");
			}
		}catch(Exception e) {
			System.out.println("An error occurred storing"+ username + "'s public key");
			e.printStackTrace();
			return false;
		}
		return false;
	}
	
	public boolean decryptCompareHash(String encryptedHash, String computedHash) {
		System.out.println("\nReceived plaintext's digest: " + computedHash);

		System.out.println("\nReceived encrypted plaintext's digest: " + encryptedHash);
		
		String decryptedHash = my_gs.RSAProvider.RSADecrypt(encryptedHash, false);//decrypt with server's private key
		System.out.println("\nReceived decrypted plaintext's digest: " + decryptedHash);
		if(computedHash.contentEquals(decryptedHash)) {
			System.out.println("\nData integrity verified: Plaintext's digest matches the received digest verified");
			return true;
		}
			return false;
	}
	
	public boolean verifyCompareHash(String pubKeyFileName, String encryptedHash, String computedHash) {
		System.out.println("\nReceived plaintext's digest: " + computedHash);

		System.out.println("\nReceived encrypted plaintext's digest: " + encryptedHash);
		
		String decryptedHash = my_gs.RSAProvider.RSADecrypt(pubKeyFileName, encryptedHash, true);//verify with client's public key
		System.out.println("\nReceived decrypted plaintext's digest: " + decryptedHash);
		if(computedHash.contentEquals(decryptedHash)) {
			System.out.println("\nData integrity verified: Plaintext's digest matches the received digest verified");
			return true;
		}
			return false;
	}
	
	
}

