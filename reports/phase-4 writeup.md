
### THREAT 5: Message Reorder, Replay, or Modification

THREAT: An adversary can potentially act as a man in the middle between two communicating parties and can intercept messages to perform a message reorder, replay attack, or modify the messages being exchanged.

EXPLOITATION EXAMPLE: An adversary can actively attack a server by:
Performing a reorder attack, where an attack can reorder messages being sent so that messages are not delivered in their intended order
Performing a replay attack, where an adversary records past messages that were exchanged and uses them to gain sensitive information by passing themselves off as one of the communicators
Performing a message modifcation, where an adversary alters the message being sent so that it is no longer distinguishable to the receiver.

SECURITY STRATEGIES: Ephemeral Diffie-Hellman, Sequencing

In the previous phase, the implementation of Ephemeral Diffie-Hellman handshake protocol ensures that communication between the client and an authenticated server is secure. This helps prevent adversaries from decrypting messages since they don't have the shared DH key as well as preventing a replay attack as the key changes with each session, meaning if an old key is used it would be obvious that the message is coming from a malicious party.
We can also introduce a sequencing number that is included in the message being sent. The client and server that they are communicating with will both have a number that sequences once with each message received and sent. This ensures that messages cannot be reordered as the message recipient checks the sequence number included in the message with that of their own. Since it should always be the same and only increments when messages are exchanged, a number in the message that is not next in the ssequence would indicated that the messages have been reordered.
Sequencing also aids in preventing replay attacks; since the attack invloves using a legitimate but already received message, an adversary can potentially gain sensitive information while pretending to be one of the communicating parties. With a sequence number, however, the adversary will only capture messages that have been sent and, therefore, only possess sequence numbers that have already been encountered, tipping off the recipient that a replay attack is occurring.
Modification can be prevented by including a hash of the message and the sequence number with the encrypted message. When a recipient receieves their message, they can confirm that the messge has not been modified by decrypting the contents of the message, computing the hash of the contents concatenated with their own sequence number, and then comparing the computed hash with the hash received from the sender.
![alt text](https://github.com/kiranpawar94/cs1653-2020su-haz79-kip28-nic89/blob/master/reports/Diagram_Threat5.png?raw=true)


### THREAT 6: File Leakage
Threat: File Servers are not trustworthy - Therefore, the security mechanisms should not be implemented in the File Servers themselves.

EXPLOITATION EXAMPLE: As of phase3, the files are stored in plaintext in the file servers. Therefore, if a File Server leaks the file, anyone can access it 
regardless whether that person is in the group or not, including users removed from groups.

SECURITY STRAEGIES: File encryption before upload, Reverse Hash Chains to provide group keys with Backward Secrecy 

The first strategy ensures the security strategy is performed outside of the File Servers. File Servers never have acces to either the files' plaintext or the encryption passwords.
On the File Server, the only data stored is the encrypted file along with a plaintext tag indicating the index of the reverse hash chain that was used as the key.
This way, users with the current group key can compute the previous keys by iteratively hashing the current key (current index - old index times). 

Group Key Exchange: Whenever a group is created, the GroupServer also computes a reverse hash chain : It starts with a random number, n, which is hashed to compute Kn. From that point, K(i) = H(Ki+1).
All the chain is precomputed to use K0 as the initial key, which the group server includes in the Tokens for users by providing a list of keys to the user that maps with the groups they belong to.
The Group Server only shares the current key, which is updated every time a user is removed. Because of the preimage resistance of secure hash functions, old users
who have been removed cannot compute Ki from K(i-1).

![alt text](https://github.com/kiranpawar94/cs1653-2020su-haz79-kip28-nic89/blob/master/reports/Diagram_Threat6.png?raw=true)


### THREAT 7: Token theft
Threat: FIle Servers can steal tokens submitted by clients authenticated by the Group Server and give them to other users so that they might use it to gain access to other File Servers.

EXPLOITATION EXAMPLE: As of phase3, the tokens already have a signature including the issuer and the subject that is hashed and signed by the Group Server for everyone to verify, in particular the Client once it is issued
and the File Server during every connection attempt. However, since the File Server is not trustworthy, we could assume it might not be verifying tokens correctly. Furthermore, it could store the issued tokens
and share them with third parties, who could then use those tokens for access to legitimate File Servers.

SECURITY STRATEGIES:
File Servers are not trustworthy, therefore, the only token validations that we can consider secure are those happening before the connection with the file server is established.
To address this issue, the client has to include the file server name ("host:port") in its token request to the Group Server. This information is then added to the token and signed by the Group Server.
When a Client receives the token from the Group Server, this token is checked for integrity using the signed digest.
When a Client attempts to connect to a File Server, the File Server's host and port are compared against the ones specified in the token by re-compuiting the digest locally and verifying the digest sent by the Group Server to compare both.
If the digests don't match, the Client isn't allowed to connect to the File Server.

![alt text](https://github.com/kiranpawar94/cs1653-2020su-haz79-kip28-nic89/blob/master/reports/Diagram_Threat7.png?raw=true)
