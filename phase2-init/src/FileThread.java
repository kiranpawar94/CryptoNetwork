/* File worker thread handles the business of uploading, downloading, and removing files for clients with valid tokens */

import java.lang.Thread;
import java.net.Socket;
import java.util.List;
import java.security.Key;
import java.security.MessageDigest;
import java.security.Security;


import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

public class FileThread extends Thread
{
	private final Socket socket;
	public String ClientPubKFile ="cl_pubKey.bin";

	public Crypto crypto;
    public Crypto.RSA RSAProvider;
    public Crypto.SHA256 DigestProvider;
	public Crypto.AES AESProvider;
	public boolean AESEnabled;
	public String sharedSecretDH;
	private FileServer my_fs;
	
	public int clientSequence;		//Sequence obtained from client
	public int fileSequence;		//Sequence from file server
	public int checkSequence;		//Comparator
	
	public FileThread(Socket _socket, FileServer my_fs)
	{
		socket = _socket;
		AESEnabled = false;
		crypto = new Crypto();
		RSAProvider = my_fs.RSAProvider;
		DigestProvider = my_fs.DigestProvider;
		this.my_fs = my_fs;
		clientSequence = 0;
		fileSequence = 0;
	
	}

	public void run()
	{
		boolean proceed = true;
		try
		{
			System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
			final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
			final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
			Envelope response;
			
			fileSequence = 0;
			
			do
			{
				
				Envelope e = (Envelope)input.readObject();
				
				
				
				if (AESEnabled) {
					e = EnvelopeEncryptionUtil.decryptEnvelope(e, AESProvider);
					if (e == null) {
						System.out.println("*** Null Envelope");
						continue;
					}
				}
				++fileSequence;
				System.out.println("\n\n\t\t\t SEQNO: " + fileSequence);
				clientSequence = (Integer)e.getObjContents().get(e.getObjContents().size()-1);
				if(clientSequence != fileSequence) {
					//Disconnect
					System.out.println("Sequence numbers mismatch\nDisconnecting\n");
					socket.close();
				}
				else {
					System.out.println("Sequence numbers match\n");
				}

				System.out.println("Request received: " + e.getMessage());

				if (e.getMessage().equals("RSA_PUBKEY_REQUEST")) {
					response = new Envelope("FAIL");
					try {
						
						response = new Envelope("RSA_SIGNED_PUBKEY");
						
						String key = RSAProvider.readFileAsString(my_fs.pubKeyFileName);
						System.out.println("File Server's RSA Key: " + key);
						String keyDigest = DigestProvider.messageDigest(key);
						System.out.println("File Server's RSA Key Digest: " + keyDigest);
						String signedKeyDigest = RSAProvider.RSAEncrypt(my_fs.privKeyFileName, keyDigest, true);
						System.out.println("\nSending server's RSA Key encrypted digest: " + signedKeyDigest);
						
						response.addObject(key);
						response.addObject(signedKeyDigest);
						
						
					}catch(Exception e_) {
						e_.printStackTrace();
					}
					
					
					
					response.addObject(++fileSequence);
					output.writeObject(response);
					continue;
				}
				else if (e.getMessage().equals("DH_HANDSHAKE")) {
					
					if(e.getObjContents().size() < 3)
					{
						response = new Envelope("FAIL");
					}
					else
					{
						response = new Envelope("FAIL");

						
						if(e.getObjContents().get(0) != null && e.getObjContents().get(1) != null) {
								Crypto.DH dhServer;
								dhServer= crypto.new DH();
								
								Key clientPubExp = (Key)e.getObjContents().get(0);
								byte[] clientIV = (byte[])e.getObjContents().get(1);
								System.out.println("Received client pubexp: " + clientPubExp.toString());
								System.out.println("Server's pubexp: " + dhServer.publicExp.toString());
								
								try {
									Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

							    	MessageDigest hash = MessageDigest.getInstance("SHA256", "BC");

							    	sharedSecretDH = new String(hash.digest(dhServer.computeSharedSecret(clientPubExp)));
							    	if(sharedSecretDH != null) {
							    		System.out.println("\n\n\n*** SHAREDSECRET: " + sharedSecretDH);
							    		
							    		response = new Envelope("OK");
							    		
							    		
										response.addObject(dhServer.publicExp);
										
										String expDigest = DigestProvider.messageDigest(new String(dhServer.publicExp.toString()));
										
										// sign with server private key
										
										String signedExpDigest = RSAProvider.RSAEncrypt(expDigest, true);
										System.out.println("\nSending Server's DH Public Exponent Signed: " + signedExpDigest);
										response.addObject(signedExpDigest);
										// init AES engine
										AESProvider = crypto.new AES(sharedSecretDH.getBytes(), clientIV);
										System.out.println("*** AES engine is set up successfully");
										AESEnabled = true;
										System.out.println("TEST: " + AESProvider.AESEncrypt("Hello World"));
										
							    	}
							    	/*checkSequence = e.getObjContents().size() -1;
									if(checkSequence != clientSequence){
										//Disconnect
										System.out.println("Connection is compromised\n");
										socket.close();
									}
									
									else if(checkSequence == clientSequence){
										System.out.println("Sequence confirmed\n");
										clientSequence++;
										response.addObject(clientSequence);
									}*/
														

									
								}catch(Exception e_) {
									response = new Envelope("FAIL");

									
									e_.printStackTrace();
								}

								
						}

					}
										

					response.addObject(++fileSequence);
					output.writeObject(response);
					
					continue;
				}

				

				// Handler to list files that this user is allowed to see
				else if(e.getMessage().equals("LFILES"))
				{
				    /* TODO: Write this handler */
					if (e.getObjContents().size() < 2) {
						response = new Envelope("FAIL-BADCONTENTS");
					}
					else {
						if (e.getObjContents().get(0) == null) {
							response = new Envelope("FAIL-BADTOKEN");
						}
						else {
							UserToken yourToken = (UserToken)e.getObjContents().get(0);
							if(checkToken(yourToken)) {
								response = new Envelope("OK");
								List<String> yourFileList = FileServer.fileList.getFiles(yourToken.getGroups());
								response.addObject(yourFileList);
							}else {
								response = new Envelope("FAIL-BADTOKEN");
							}
						}
					}
					
					response.addObject(++fileSequence);
					
					if (AESEnabled) {
						Envelope encryptedEnvelope = EnvelopeEncryptionUtil.encryptEnvelope(response, AESProvider);
						output.writeObject(encryptedEnvelope);
					} else {
						output.writeObject(response);
					}
				}
				else if(e.getMessage().equals("UPLOADF"))
				{

					if(e.getObjContents().size() < 4)
					{
						response = new Envelope("FAIL-BADCONTENTS");
					}
					else
					{
						if(e.getObjContents().get(0) == null) {
							response = new Envelope("FAIL-BADPATH");
						}
						if(e.getObjContents().get(1) == null) {
							response = new Envelope("FAIL-BADGROUP");
						}
						if(e.getObjContents().get(2) == null) {
							response = new Envelope("FAIL-BADTOKEN");
						}
						else {
							String remotePath = (String)e.getObjContents().get(0);
							String group = (String)e.getObjContents().get(1);
							UserToken yourToken = (UserToken)e.getObjContents().get(2); //Extract token
							if(!(checkToken(yourToken))) {
								response = new Envelope("FAIL-BADTOKEN");
							}
							else {
								if (FileServer.fileList.checkFile(remotePath)) {
									System.out.printf("Error: file already exists at %s\n", remotePath);
									response = new Envelope("FAIL-FILEEXISTS"); //Success
								}
								else if (!yourToken.getGroups().contains(group)) {
									System.out.printf("Error: user missing valid token for group %s\n", group);
									response = new Envelope("FAIL-UNAUTHORIZED"); //Success
								}
								else  {
									File file = new File("shared_files/"+remotePath.replace('/', '_'));
									file.createNewFile();
									FileOutputStream fos = new FileOutputStream(file);
									System.out.printf("Successfully created file %s\n", remotePath.replace('/', '_'));
									response = new Envelope("READY"); //Success
									response.addObject(++fileSequence);
									if (AESEnabled) {
										Envelope encryptedEnvelope = EnvelopeEncryptionUtil.encryptEnvelope(response, AESProvider);
										output.writeObject(encryptedEnvelope);
										encryptedEnvelope = (Envelope)input.readObject();
										e = EnvelopeEncryptionUtil.decryptEnvelope(encryptedEnvelope, AESProvider);
										++fileSequence;
									} else {
										output.writeObject(response);
										e = (Envelope)input.readObject();
										++fileSequence;
									}							

									while (e.getMessage().compareTo("CHUNK")==0) {
										fos.write((byte[])e.getObjContents().get(0), 0, (Integer)e.getObjContents().get(1));
										response = new Envelope("READY"); //Success
										response.addObject(++fileSequence);
										if (AESEnabled) {
											Envelope encryptedEnvelope = EnvelopeEncryptionUtil.encryptEnvelope(response, AESProvider);
											output.writeObject(encryptedEnvelope);
											encryptedEnvelope = (Envelope)input.readObject();
											++fileSequence;
											e = EnvelopeEncryptionUtil.decryptEnvelope(encryptedEnvelope, AESProvider);
										} else {
											output.writeObject(response);
											e = (Envelope)input.readObject();
											++fileSequence;
										}													
									}
									
									if(e.getMessage().compareTo("EOF")==0) {
										System.out.printf("Transfer successful file %s\n", remotePath);
										FileServer.fileList.addFile(yourToken.getSubject(), group, remotePath);
										response = new Envelope("OK"); //Success
										
									}
									else {
										System.out.printf("Error reading file %s from client\n", remotePath);
										response = new Envelope("ERROR-TRANSFER"); //Success
									}
									fos.close();
								}
							}
						}
					}
					response.addObject(++fileSequence);
					if (AESEnabled) {
						Envelope encryptedEnvelope = EnvelopeEncryptionUtil.encryptEnvelope(response, AESProvider);
						output.writeObject(encryptedEnvelope);
					} else {
						output.writeObject(response);
					}
				}
				else if (e.getMessage().compareTo("DOWNLOADF")==0) {

					String remotePath = (String)e.getObjContents().get(0);
					Token t = (Token)e.getObjContents().get(1);
					if(!(checkToken(t))) {
						response = new Envelope("FAIL-BADTOKEN");
					}
					else {
					
						ShareFile sf = FileServer.fileList.getFile("/"+remotePath);
						if (sf == null) {
							System.out.printf("Error: File %s doesn't exist\n", remotePath);
							e = new Envelope("ERROR_FILEMISSING");
							e.addObject(++fileSequence);
							if (AESEnabled) {
								Envelope encryptedEnvelope = EnvelopeEncryptionUtil.encryptEnvelope(e, AESProvider);
								output.writeObject(encryptedEnvelope);
							} else {
								output.writeObject(e);
							}
								
						}
						
						else if (!t.getGroups().contains(sf.getGroup())){
							System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
							e = new Envelope("ERROR_PERMISSION");
							e.addObject(++fileSequence);
							if (AESEnabled) {
								Envelope encryptedEnvelope = EnvelopeEncryptionUtil.encryptEnvelope(e, AESProvider);
								output.writeObject(encryptedEnvelope);
							} else {
								output.writeObject(e);
							}
						}
						else {
							
							try
							{
								String group = sf.getGroup();

								File f = new File("shared_files/_"+remotePath.replace('/', '_'));
								if (!f.exists()) {
									System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
									e = new Envelope("ERROR_NOTONDISK");
									e.addObject(++fileSequence);
									if (AESEnabled) {
										Envelope encryptedEnvelope = EnvelopeEncryptionUtil.encryptEnvelope(e, AESProvider);
										output.writeObject(encryptedEnvelope);
									} else {
										output.writeObject(e);
									}												
									
								}
								else {
									FileInputStream fis = new FileInputStream(f);
									
									do {
										byte[] buf = new byte[4096];
										if (e.getMessage().compareTo("DOWNLOADF")!=0) {
											System.out.printf("Server error: %s\n", e.getMessage());
											break;
										}
										e = new Envelope("CHUNK");
										int n = fis.read(buf); //can throw an IOException
										if (n > 0) {
											System.out.printf(".");
										} else if (n < 0) {
											System.out.println("Read error: File might be empty");
											
										}
										
										
										e.addObject(buf);
										e.addObject(new Integer(n));
										e.addObject(++fileSequence);
										if (AESEnabled) {
											Envelope encryptedEnvelope = EnvelopeEncryptionUtil.encryptEnvelope(e, AESProvider);
											output.writeObject(encryptedEnvelope);
											encryptedEnvelope = (Envelope)input.readObject();
											++fileSequence;
											e = EnvelopeEncryptionUtil.decryptEnvelope(encryptedEnvelope, AESProvider);
										} else {
											output.writeObject(e);
											e = (Envelope)input.readObject();
											++fileSequence;
										}													
										
										
									}
									while (fis.available()>0);
									
							//	If server indicates success, return the member list
									if(e.getMessage().compareTo("DOWNLOADF")==0)
									{
										
										e = new Envelope("EOF");
										e.addObject(group);
										e.addObject(++fileSequence);
										if (AESEnabled) {
											Envelope encryptedEnvelope = EnvelopeEncryptionUtil.encryptEnvelope(e, AESProvider);
											output.writeObject(encryptedEnvelope);
											encryptedEnvelope = (Envelope)input.readObject();
											++fileSequence;
											e = EnvelopeEncryptionUtil.decryptEnvelope(encryptedEnvelope, AESProvider);
										} else {
											output.writeObject(e);
											e = (Envelope)input.readObject();
											++fileSequence;
										}			

										if(e.getMessage().compareTo("OK")==0) {
											System.out.printf("File data upload successful\n");
										}
										else {
											
											System.out.printf("Upload failed: %s\n", e.getMessage());

										}
										
									}
									else {
										
										System.out.printf("Upload failed: %s\n", e.getMessage());
										
									}
								}
						}
						catch(Exception e1)
						{
							System.err.println("Error: " + e.getMessage());
							e1.printStackTrace(System.err);

						}
					}
					}
				}
				else if (e.getMessage().compareTo("DELETEF")==0) {

					String remotePath = (String)e.getObjContents().get(0);
					Token t = (Token)e.getObjContents().get(1);
					int tmpseqno = (int)(e.getObjContents().get(2));
					
					if(!(checkToken(t))) {
						response = new Envelope("FAIL-BADTOKEN");
					}
					else {
						ShareFile sf = FileServer.fileList.getFile("/"+remotePath);
						if (sf == null) {
							System.out.printf("Error: File %s doesn't exist\n", remotePath);
							e = new Envelope("ERROR_DOESNTEXIST");
						}
						else if (!t.getGroups().contains(sf.getGroup())){
							System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
							e = new Envelope("ERROR_PERMISSION");
						}
						else {

							try
							{


								File f = new File("shared_files/"+"_"+remotePath.replace('/', '_'));

								if (!f.exists()) {
									System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
									e = new Envelope("ERROR_FILEMISSING");
								}
								else if (f.delete()) {
									System.out.printf("File %s deleted from disk\n", "_"+remotePath.replace('/', '_'));
									FileServer.fileList.removeFile("/"+remotePath);
									e = new Envelope("OK");
								}
								else {
									System.out.printf("Error deleting file %s from disk\n", "_"+remotePath.replace('/', '_'));
									e = new Envelope("ERROR_DELETE");
								}
							
							
							}
							catch(Exception e1)
							{
								System.err.println("Error: " + e1.getMessage());
								e1.printStackTrace(System.err);
								e = new Envelope(e1.getMessage());
							}
						}
						e.addObject(++fileSequence);
						if (AESEnabled) {
							Envelope encryptedEnvelope = EnvelopeEncryptionUtil.encryptEnvelope(e, AESProvider);
							output.writeObject(encryptedEnvelope);
						} else {
							output.writeObject(e);
						}

					}
				}
				else if(e.getMessage().equals("DISCONNECT"))
				{
					System.out.println("*** Disconnection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
					socket.close();
					proceed = false;
				}
			} while(proceed);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
	
	
	
	
	public boolean checkToken(UserToken yourToken) {
		Token t = (Token)yourToken;
		String plaintext = t.getIssuer() + t.getSubject() + t.getFileServerName();

		String hash = DigestProvider.messageDigest(plaintext);

		//Decrypt with server's public key
		String verified = RSAProvider.RSADecrypt("pubkey",t.getSignature(), true);

		if (verified.equals(hash)) {
			System.out.println("Token's digest matches the digest signed by the Server. Verification successful");
			return true;
		}
		else {
			return false;
		}
	}

}