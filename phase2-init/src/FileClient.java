/* FileClient provides all the client functionality regarding the file server */

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.util.*;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.util.encoders.Base64;

import java.security.Key;
import java.security.MessageDigest;
import java.security.Security;

public class FileClient extends Client implements FileClientInterface {
	
	public String hostAddress;

	public Crypto.SHA256 DigestProvider;
	public Crypto.RSA RSAProvider;
	public String sharedSecretDH; //D-H Shared secret for the session (Symmetric key for encryption)
	public Crypto.AES AESProvider;
	public boolean AESEnabled;
	public Crypto crypto;
	
	public int clientSequence;
	public int fileSequence;

	String pubKeyFileName; //RSA Public key for the curret user
	String privKeyFileName; //RSA Private key for the current user
	int seqno;
	public FileClient() {
		crypto = new Crypto();
		DigestProvider = crypto.new SHA256();
		AESEnabled = false;
		clientSequence = 0;
		try {
			// server public key is precondition
			File fpub = new File("pubkey");
			if (!(fpub.exists())) {
				System.err.println("Server's Public Key not found in the path. Shutting down");
			}
		} catch(Exception e) {
			System.err.println("Error getting server RSA key " + e.getMessage());
			e.printStackTrace(System.err);
		}

	}
	
	@Override
	public boolean connect(final String server, final int port) {
		System.out.println("attempting to connect");
		clientSequence = 0;
		
		try {
			sock = new Socket(server, port);
			System.out.println("Connected to " + server + " on port " + port);
			hostAddress = String.valueOf(server) + "_" + String.valueOf(port);
			output = new ObjectOutputStream(sock.getOutputStream());
			input = new ObjectInputStream(sock.getInputStream());
			
		}
		catch(Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
			return false;
		}
		return true;
	}
	
	
	
	// KP NOTES for STEPS  +++
		/* Initial connection
		1. Client connects to server
		2. Client receives public key from server
		3. Client hashes public key and determines whether they want to connect to server or not
		Subsequent connections
		1. Client connects to server
		2. Client receives public key from server
		3. Client compares public key with hashed public
		4. If not the same disconnect, if same connect
		5. Client encrypts a number with public key, sends it over to file server
		6. File server decrypts public key with private key, sends number back to client
		7. If decrypted number matches original, connect, otherwise disconnect
		*/
	
	public boolean authenticateServer(String username) {
		/* User's RSA Keys were setup during GROUP SERVER handshake
		 * Otherwise, can't verify tokens!!*/
		pubKeyFileName = username + "_pubkey";
		privKeyFileName = username + "_privkey";	

		RSAProvider = crypto.new RSA(pubKeyFileName, privKeyFileName);
		
		String FsPubKeyFile = hostAddress + "_pubkey";
        
		File fpub = new File(pubKeyFileName);
		File fpriv = new File(privKeyFileName);
	

		try {
					// Request Authentication. 
					Envelope env = new Envelope("RSA_PUBKEY_REQUEST");
					
					env.addObject(++clientSequence);
					
					output.writeObject(env); 

					// Read the public key that should follow HANDSHAKE? request
				    Envelope response = (Envelope)input.readObject();
					++clientSequence;
				    if (response.getMessage().equals("RSA_SIGNED_PUBKEY") && response.getObjContents().size() == 3) {
				    	
				    	String serverPubKey = (String)response.getObjContents().get(0);
				    	
				    	//Store temporarily for decryption of signed digest
				    	this.storeTmpServerPubKey(hostAddress, serverPubKey);
				    	
				    	String signedServerPubKeyDigest = (String)response.getObjContents().get(1);
				    	String serverPubKeyDigest = this.DigestProvider.messageDigest(serverPubKey);
				    	String serverPubKeyFileName = "." + File.separator + "fileservers_pubkeys" + File.separator + hostAddress + "_pubkey";
				    	
				    	if (this.verifyCompareHash(serverPubKeyFileName + "tmp", signedServerPubKeyDigest, serverPubKeyDigest)) {
				    		this.deleteTmpServerPubKey(hostAddress);
				    		System.out.println("Received FileServer's key successfully verified from origin. Server authentication can proceed.");
							//// COMPARE PROVIDED PUBLIC KEY WITH STORED ONE, OR STORE IF IT'S FROM A NEW SERVER
							File tmpDir = new File("." + File.separator + "fileservers_pubkeys");
							
							//CHECK DIRECTORY EXISTS
							if(tmpDir.exists() && tmpDir.isDirectory()) {
								System.out.println("\n\n\t/filservers_pubkeys found");
								//CHECK IF SERVER'S PUBLIC KEY  IS ALREADY STORED
								File tmpFile = new File(serverPubKeyFileName);
								if(tmpFile.exists() && tmpFile.isFile()) {

									System.out.println("\n\n\t" + hostAddress + "_pubkey found");
									//READ PUBLIC KEY FROM DISK
									String storedPubKey = RSAProvider.readFileAsString(serverPubKeyFileName);
									//COMPARE WITH RECEIVED KEY 
									if(storedPubKey.contentEquals(serverPubKey)) {

										System.out.println("\n\n\t" + hostAddress + "_pubkey matches");
										return true;
									} else {
										response = new Envelope("SECURITY_ERROR_RSA");
										System.out.println("\n*** SECURITY ERROR: File Server's key doesn't match its digest stored in the server. File Server's sysadmin Should check if this is an error.");
									}
									
								}else { // NEW SERVER
									//STORE KEY DIGEST
									if(storeServerPubKey(hostAddress, serverPubKey)) {

										System.out.println("\n\n\t" + hostAddress + "_pubkey stored");
										//OK
										return true;
									}
									
								}
							}else {
								//FIRST SERVER USER CONNECTS TO -> CREATE DIRECTORY AND STORE PUBLIC KEY
								if(tmpDir.mkdir()) {
									if(storeServerPubKey(hostAddress, serverPubKey)) {
										System.out.println("\n\n\t" + hostAddress + "_pubkey stored");
										return true;
										//OK
									}
									
								}else {
									response = new Envelope("SECURITY_ERROR_RSA");
									System.out.println("\nError encountered while creating the directory ./fileservers_pubkeys. Please, check the current working directory");
								}
							}
							
						}else {
							response = new Envelope("SECURITY_ERROR_RSA");

							System.out.println("\n*** SECURITY ERROR: Received key's digest doesn't match the decrypted digest. Data integrity might have been compromised during the communication.");
							this.deleteTmpServerPubKey(hostAddress);
				    	}
				    	
				    	
				    	
				    } else {
				    	System.out.println("RSA handshake error: Wrong message format from server");
				    }
					
				    
		}catch(Exception e) {
			e.printStackTrace();
		}
		return false;
				    
	}
	
	


	public boolean delete(String filename, UserToken token) {
		String remotePath;
		if (filename.charAt(0)=='/') {
			remotePath = filename.substring(1);
		}
		else {
			remotePath = filename;
		}
		Envelope env = new Envelope("DELETEF"); //Success
	    env.addObject(remotePath);
	    env.addObject(token);
	    env.addObject(++clientSequence);
	    
	    try {
			if (AESEnabled) {
				Envelope encryptedEnvelope = EnvelopeEncryptionUtil.encryptEnvelope(env, AESProvider);
				output.writeObject(encryptedEnvelope);
				
				encryptedEnvelope = (Envelope)input.readObject();
				env = EnvelopeEncryptionUtil.decryptEnvelope(encryptedEnvelope, AESProvider);
			} else {
				output.writeObject(env);
				env = (Envelope)input.readObject();
			}
			
			++clientSequence;
			fileSequence = (Integer)env.getObjContents().get(env.getObjContents().size()-1);
			if(fileSequence != clientSequence) {
				System.out.println("Sequence number mismatch\nDisconnecting\n");
				disconnect();
			}
			
			else {
				System.out.println("Sequence numbers match\n");
			}
		    
			if (env.getMessage().compareTo("OK")==0) {
				System.out.printf("File %s deleted successfully\n", filename);				
			}
			else {
				System.out.printf("Error deleting file %s (%s)\n", filename, env.getMessage());
				return false;
			}			
		} catch (IOException e1) {
			e1.printStackTrace();
		} catch (ClassNotFoundException e1) {
			e1.printStackTrace();
		}
	    	
		return true;
	}

	public boolean download(String sourceFile, String destFile, UserToken token) {
				if (sourceFile.charAt(0)=='/') {
					sourceFile = sourceFile.substring(1);
				}
		
				File file = new File(destFile);
			    try {
			    				
				
				    if (!file.exists()) {
				    	file.createNewFile();
					    FileOutputStream fos = new FileOutputStream(file);
					    
					    Envelope env = new Envelope("DOWNLOADF"); //Success
					    env.addObject(sourceFile);
					    env.addObject(token);
					    env.addObject(++clientSequence);

						if (AESEnabled) {
							Envelope encryptedEnvelope = EnvelopeEncryptionUtil.encryptEnvelope(env, AESProvider);
							output.writeObject(encryptedEnvelope);
							encryptedEnvelope = (Envelope)input.readObject();
							env = EnvelopeEncryptionUtil.decryptEnvelope(encryptedEnvelope, AESProvider);
						} else {
							output.writeObject(env);
							env = (Envelope)input.readObject();
						}
						
						++clientSequence;
						fileSequence = (Integer)env.getObjContents().get(env.getObjContents().size()-1);
						if(fileSequence != clientSequence) {
							System.out.println("Sequence number mismatch\nDisconnecting\n");
							disconnect();
						}
						
						else {
							System.out.println("Sequence numbers match\n");
						}
					    
						while (env.getMessage().compareTo("CHUNK")==0) { 
								fos.write((byte[])env.getObjContents().get(0), 0, (Integer)env.getObjContents().get(1));
								System.out.printf(".");
								env = new Envelope("DOWNLOADF"); //Success
								env.addObject(++clientSequence);
								if (AESEnabled) {
									Envelope encryptedEnvelope = EnvelopeEncryptionUtil.encryptEnvelope(env, AESProvider);
									output.writeObject(encryptedEnvelope);
									encryptedEnvelope = (Envelope)input.readObject();
									env = EnvelopeEncryptionUtil.decryptEnvelope(encryptedEnvelope, AESProvider);
								} else {
									output.writeObject(env);
									env = (Envelope)input.readObject();
								}
								++clientSequence;
								fileSequence = (Integer)env.getObjContents().get(env.getObjContents().size()-1);
								if(fileSequence != clientSequence) {
									System.out.println("Sequence number mismatch\nDisconnecting\n");
									disconnect();
								}
								
								else {
									System.out.println("Sequence numbers match\n");
								}
						}										
						fos.close();
						
					    if(env.getMessage().compareTo("EOF")==0) {
					    	 String fileGroup = (String)env.getObjContents().get(0);
					    	 fos.close();
								System.out.printf("\nTransfer successful file %s\n", sourceFile);
								env = new Envelope("OK"); //Success
								env.addObject(++clientSequence);
								if (AESEnabled) {
									Envelope encryptedEnvelope = EnvelopeEncryptionUtil.encryptEnvelope(env, AESProvider);
									output.writeObject(encryptedEnvelope);
									
									 if(AESEnabled) {
										String groupKey = ((Token)token).getGroupKey(fileGroup).split("__HASHINDEX")[0];
										groupKey = new String(Base64.decode(groupKey.getBytes()));
										int hashIndex = Integer.parseInt(((Token)token).getGroupKey(fileGroup).split("__HASHINDEX__=")[1]);
										Crypto.AES fileAES = crypto.new AES(groupKey.getBytes(), Arrays.copyOfRange(groupKey.getBytes(), 0, 16));
											
										if(fileAES.decryptFile(destFile, groupKey, hashIndex)) {
											System.out.println("File successfully decrypted");
										 
										}else {

											System.out.println("Decryption error, deleting file");
											return false;
										 }
										 
									 }
									 
									 
								} else {
									output.writeObject(env);
								}
								
						}
						else {
								System.out.printf("Error reading file %s (%s)\n", sourceFile, env.getMessage());
								file.delete();
								return false;								
						}
				    }    
					 
				    else {
						System.out.printf("Error couldn't create file %s\n", destFile);
						return false;
				    }
								
			
			    } catch (IOException e1) {
			    	
			    	System.out.printf("Error couldn't create file %s\n", destFile);
			    	return false;
			    
					
				}
			    catch (ClassNotFoundException e1) {
					e1.printStackTrace();
				}
				 return true;
	}

	@SuppressWarnings("unchecked")
	public List<String> listFiles(UserToken token) {
		 try
		 {
			 Envelope message = null, e = null;
			 //Tell the server to return the member list
			 message = new Envelope("LFILES");
			 message.addObject(token); //Add requester's token
			 message.addObject(++clientSequence);

			if (AESEnabled) {
				Envelope encryptedEnvelope = EnvelopeEncryptionUtil.encryptEnvelope(message, AESProvider);
				output.writeObject(encryptedEnvelope);
				encryptedEnvelope = (Envelope)input.readObject();
				e = EnvelopeEncryptionUtil.decryptEnvelope(encryptedEnvelope, AESProvider);
			} else {
				output.writeObject(message);
				e = (Envelope)input.readObject();
			}
			++clientSequence;
			fileSequence = (Integer)e.getObjContents().get(e.getObjContents().size()-1);
			if(fileSequence != clientSequence) {
				System.out.println("Sequence number mismatch\nDisconnecting\n");
				disconnect();
			}
			
			else {
				System.out.println("Sequence numbers match\n");
			}
			 //If server indicates success, return the member list
			 if(e.getMessage().equals("OK"))
			 { 
				return (List<String>)e.getObjContents().get(0); //This cast creates compiler warnings. Sorry.
			 } else {
				System.out.println("Unsuccessful request");
				 return null;
			 }
			 
		 }
		 catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
				return null;
			}
	}

	public boolean upload(String sourceFile, String destFile, String group,
			UserToken token) {
			
		if (destFile.charAt(0)!='/') {
			 destFile = "/" + destFile;
		 }
		
		try
		 {
			 
			 Envelope message = null, env = null;
			 //Tell the server to return the member list
			 message = new Envelope("UPLOADF");
			 message.addObject(destFile);
			 message.addObject(group);
			 message.addObject(token); //Add requester's token
			 message.addObject(++clientSequence);

			if (AESEnabled) {
				Envelope encryptedEnvelope = EnvelopeEncryptionUtil.encryptEnvelope(message, AESProvider);
				output.writeObject(encryptedEnvelope);
				encryptedEnvelope = (Envelope)input.readObject();
				env = EnvelopeEncryptionUtil.decryptEnvelope(encryptedEnvelope, AESProvider);
			} else {
				output.writeObject(message);
				env = (Envelope)input.readObject();
			}

			 String groupKey = ((Token)token).getGroupKey(group).split("__HASHINDEX")[0];
			 
			 groupKey = new String(Base64.decode(groupKey.getBytes()));
			 System.out.println("KEY BITS : " + groupKey.getBytes().length * 8);
			 int hashIndex = Integer.parseInt(((Token)token).getGroupKey(group).split("__HASHINDEX__=")[1]);
			 Crypto.AES fileAES = crypto.new AES(groupKey.getBytes(), Arrays.copyOfRange(groupKey.getBytes(), 0, 16));
			 if(AESEnabled) {
				 if(fileAES.encryptFile(sourceFile, groupKey, hashIndex)) {
					 System.out.println("File successfully encrypted before upload");
				 
				 }else {

					 System.out.println("Encryption error before upload");
					 return false;
				 }
				 sourceFile += ".enc";
			 }

			++clientSequence; 
			fileSequence = (Integer)env.getObjContents().get(env.getObjContents().size()-1);
			if(fileSequence != clientSequence) {
				System.out.println("Sequence number mismatch\nDisconnecting\n");
				disconnect();
			}
			
			else {
				System.out.println("Sequence numbers match\n");
			}
			
			 FileInputStream fis = new FileInputStream(sourceFile);
			 			 
			 //If server indicates success, return the member list
			 if(env.getMessage().equals("READY"))
			 { 
				System.out.printf("Meta data upload successful\n");
				
			}
			 else {
				
				 System.out.printf("Upload failed: %s\n", env.getMessage());
				 return false;
			 }
			 System.out.printf("3333", env.getMessage());
		 	
			 do {
				 byte[] buf = new byte[4096];
				 	if (env.getMessage().compareTo("READY")!=0) {
				 		System.out.printf("Server error: %s\n", env.getMessage());
				 		return false;
				 	}
				 	message = new Envelope("CHUNK");
					int n = fis.read(buf); //can throw an IOException
					if (n > 0) {
						System.out.printf(".");
					} else if (n < 0) {
						System.out.println("Read error");
						return false;
					}
					
					message.addObject(buf);
					message.addObject(new Integer(n));
					message.addObject(++clientSequence);

					if (AESEnabled) {
						Envelope encryptedEnvelope = EnvelopeEncryptionUtil.encryptEnvelope(message, AESProvider);
						output.writeObject(encryptedEnvelope);
						encryptedEnvelope = (Envelope)input.readObject();
						env = EnvelopeEncryptionUtil.decryptEnvelope(encryptedEnvelope, AESProvider);
						
					} else {
						output.writeObject(message);
						env = (Envelope)input.readObject();
					}					
					++clientSequence;
					fileSequence = (Integer)env.getObjContents().get(env.getObjContents().size()-1);
					if(fileSequence != clientSequence) {
						System.out.println("Sequence number mismatch\nDisconnecting\n");
						disconnect();
					}
					
					else {
						System.out.println("Sequence numbers match\n");
					}
										
			 }
			 while (fis.available()>0);		 
					 
			 //If server indicates success, return the member list
			 if(env.getMessage().compareTo("READY")==0)
			 { 
				
				message = new Envelope("EOF");
				message.addObject(++clientSequence);
				
				if (AESEnabled) {
					Envelope encryptedEnvelope = EnvelopeEncryptionUtil.encryptEnvelope(message, AESProvider);
					output.writeObject(encryptedEnvelope);
					encryptedEnvelope = (Envelope)input.readObject();
					env = EnvelopeEncryptionUtil.decryptEnvelope(encryptedEnvelope, AESProvider);
					File f = new File(sourceFile);
					f.delete(); //delete .enc file
				} else {
					output.writeObject(message);
					env = (Envelope)input.readObject();
				}
				++clientSequence;
				fileSequence = (Integer)env.getObjContents().get(env.getObjContents().size()-1);
				if(fileSequence != clientSequence) {
					System.out.println("Sequence number mismatch\nDisconnecting\n");
					disconnect();
				}
				
				else {
					System.out.println("Sequence numbers match\n");
				}
				// output.writeObject(message);
				
				// env = (Envelope)input.readObject();
				
				if(env.getMessage().compareTo("OK")==0) {
					
					System.out.printf("\nFile data upload successful\n");
				}
				else {
					
					 System.out.printf("\nUpload failed: %s\n", env.getMessage());
					 return false;
				 }
				
			}
			 else {
				
				 System.out.printf("Upload failed: %s\n", env.getMessage());
				 return false;
			 }
			 
		 }catch(Exception e1)
			{
				System.err.println("Error: " + e1.getMessage());
				e1.printStackTrace(System.err);
				return false;
				}
		 return true;
	}

	public boolean doHandshakeDH(String username)
	{
		try
		{
			
			if(!this.authenticateServer(username)) {
				return false;
			}
			System.out.println("File Server successfully authenticated");
			/* DH */		
			Crypto.DH dhClient;
			dhClient= crypto.new DH();
			
			Envelope message = null, response = null;
		 		 	
			message = new Envelope("DH_HANDSHAKE");
			message.addObject(dhClient.publicExp);
			byte[] clientIV = crypto.generateRandomBytes(16);
			message.addObject(clientIV);
			message.addObject(++clientSequence);
			
			System.out.println("Client's DH Public Exponent: " + dhClient.publicExp.toString());
			// send user's public exp to the server
			output.writeObject(message);
		
			//Get the response from the server
			response = (Envelope)input.readObject();
			System.out.println("RESPONSE " + response.getMessage());
			//Successful response
			++clientSequence;
			fileSequence = (Integer)response.getObjContents().get(response.getObjContents().size()-1);
			if(fileSequence != clientSequence) {
				System.out.println("Sequence number mismatch\nDisconnecting\n");
				disconnect();
			}
			
			else {
				System.out.println("Sequence numbers match\n");
			}
			
			if(response.getMessage().equals("OK"))
			{
				System.out.println("RECEIVED OK FROM SERVER");
				//If there is a token in the Envelope, return it 
				ArrayList<Object> temp = null;
				temp = response.getObjContents();
				
				if(temp.size() == 3)
				{
					Key serverPubExp = (Key)temp.get(0);					
					String serverPubExpDigest = DigestProvider.messageDigest(serverPubExp.toString());
					String signedServerPubExp = (String)temp.get(1);
					
					
					System.out.println("Received  server's Public Exponent: " + serverPubExp.toString());
					System.out.println("Received  server's Signed Public Exponent: " + signedServerPubExp.toString());
					System.out.println("Server's Public Exponent: " + dhClient.publicExp.toString());
					//COMPARE RECEIVED CLIENT'S PUBLIC EXPONENT'S HASH WITH THE LOCALLY COMPUTED ONE
					if(verifyCompareHash("pubkey", signedServerPubExp, serverPubExpDigest)) { //Verify with server's public key
						

						try {
							Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

							MessageDigest hash = MessageDigest.getInstance("SHA256", "BC");

							sharedSecretDH = new String(hash.digest(dhClient.computeSharedSecret(serverPubExp)));
							if(sharedSecretDH != null) {
								System.out.println("\n\n\n*** SHAREDSECRET: " + sharedSecretDH);
								// setup AES engine
								AESEnabled = true; 
								AESProvider = crypto.new AES(sharedSecretDH.getBytes(), clientIV);
								System.out.println("*** AES engine is successfully set up");
								System.out.println("TEST: " + AESProvider.AESEncrypt("Hello World"));
								seqno = 0;
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

	 public boolean verifyCompareHash(String pubKeyFileName, String encryptedHash, String computedHash) {
			System.out.println("\nReceived plaintext's digest: " + computedHash);

			System.out.println("\nReceived encrypted plaintext's digest: " + encryptedHash);
			System.out.println("/n/n/n//t/tAttempting to get key from " + pubKeyFileName + "\n\n\n");
			String decryptedHash = RSAProvider.RSADecrypt(pubKeyFileName, encryptedHash, true);
			System.out.println("\nReceived decrypted plaintext's digest: " + decryptedHash);
			if(computedHash.contentEquals(decryptedHash)) {
				System.out.println("\nData integrity verified: Plaintext's digest matches the received digest verified");
				return true;
			}
				return false;
		}	 
	 
	 public boolean storeServerPubKey(String serverName, String serverPubKey) {
			try {
				File tmpFile = new File("." + File.separator + "fileservers_pubkeys" + File.separator + serverName + "_pubkey");
				if(tmpFile.createNewFile()) {
					FileWriter myWriter = new FileWriter("." + File.separator + "fileservers_pubkeys" + File.separator + serverName + "_pubkey");
					myWriter.write(serverPubKey);
					myWriter.close();	
					System.out.println("Successfully stored " + serverName + "'s public key");
					return true;
				}else {
					System.out.println("Error encountered while creating the file ./fileservers_pubkeys/" + serverName + "_pubkey . Please, check the current working directory");
				}
			}catch(Exception e) {
				System.out.println("An error occurred storing"+ serverName + "'s public key");
				e.printStackTrace();
				return false;
			}
			return false;
		}
	 public boolean storeTmpServerPubKey(String serverName, String serverPubKey) {
			try {
				File tmpDir = new File("." + File.separator + "fileservers_pubkeys");
				
				//CHECK DIRECTORY EXISTS
				if(!(tmpDir.exists() && tmpDir.isDirectory())) {
					tmpDir.mkdir();
				}
				File tmpFile = new File("." + File.separator + "fileservers_pubkeys" + File.separator + serverName + "_pubkeytmp");
				if(tmpFile.createNewFile()) {
					FileWriter myWriter = new FileWriter("." + File.separator + "fileservers_pubkeys" + File.separator + serverName + "_pubkeytmp");
					myWriter.write(serverPubKey);
					myWriter.close();	
					return true;
				}
				
			}catch(Exception e) {
				e.printStackTrace();
				return false;
			}
			return false;
		}
	 
	 public boolean deleteTmpServerPubKey(String serverName) {
		 try {
				File tmpFile = new File("." + File.separator + "fileservers_pubkeys" + File.separator + serverName + "_pubkeytmp");
				if(tmpFile.delete()) {
					return true;
				}
				
			}catch(Exception e) {
				e.printStackTrace();
				return false;
			}
			return false;
	 }
	 
		
}