

### THREAT 1: UNAUTHORIZED TOKEN ISSUANCE 

THREAT: At the current development stage, previous to completing phase3, the group server just responds to GET requests based on the username parameter passed by the user by calling  the function createToken with the same parameter. If the user is found, the token is issued. 

EXPLOITATION EXAMPLE: This vulnerability is exploitable by both active and passive adversaries. The assignment description states that we will assume both non-trustworthy clients(active attackers) and passive attackers. 

Active attacks: An active attacker doesn’t even need to perform packet injection to carry over an active attack: The GUI / CLI allow clients to adopt anybody’s identity without further authentication by just typing the chosen username, as long as the impersonated user exists. 

Passive attacks: Anyone monitoring traffic can launch a replay attack by capturing the unencrypted traffic and re-sending a GET request without even having to guess a username. The token will then be granted by the Group Server without further question

SECURITY STRATEGIES: PUBLIC-KEY-BASED AUTHENTICATION + ENCRYPTION -> **Ephemeral Diffie-Hellman key exchange signed with RSA (DHE-RSA)**

The authentication is provided by the public-key encryption scheme RSA as soon as a client requests a token: 
 - The server's key is shipped with all parts of the Application, so clients and file servers can verify messages from the Server. The server is trusted according to the current Trust Model.
 - The client sends his/her public key encrypted using the Server's public key.
   - If it's the first time the client connects to the Server, the Server trusts this connection and stores the client's public key associated to the clent's name. This implementation assumes the client works closely with the Server admin to connect as soon as the account is created. This scheme is equivalent to the admin providing the user with a one-time initial password, or with an RSA-keypair. However, the advantage is that the user can generate its own RSA keypair without intermediaries.
   - If it's not the first time the client connects to the Server, the Server compares the provided key with the one stored associated to the client. If the keys match, the Server trusts the client.
If the client is correctly authenticated, the Server will grant the token.

The next step is protect the data in the subsequent messages Client<->Server. For this purpose, symmetric encryption (AES-256) will be used for efficiency. To compute the shared key, the Client and the Server will agree on a shared secret using an RSA-signed Ephemeral D-H protocol. At this point, both agents are authenticated by the fact that they each know their private key. If they don't, they can't decrypt messages during the D-H handshake, so they can't compute the shared secret. Ephemeral simply means the D-H key pairs are randomly generated for each connection. This way of agreeing on a shared secret also provides forward secrecy, since the Diffie-Hellman handshake uses fresh exponents, modulo and generator each time a Token is requested (even by the same user).

Furthermore, for any subsequent request, the ClientApp will store the current user's name to enforce new authentication if it changes, or keep re-using the same RSA keypair if it doesn't change.

VALIDITY :  
As described in the diagram below, kB-1 and kS-1 are the RSA private exponents used to sign the messages during the DHE key agreement. This means RSA is just used to provide data integrity and prevent a MITM attack during the key agreement. Therefore, anyone can SEE the D-H handshake, which still looks random to anyone who doesn't have the D-H private exponents.
If the RSA private exponents are compromised, FUTURE communications can be intercepted: an attacker can intercept the client's connection and replace the D-H's private exponent by a known one to be able to compute the shared secret. 
HOWEVER, **previous communications remain secret**: The attacker would only be able to see (g^b mod p) during D-H key exchange, which looks random (whatever g^b mod p is, it belongs to a congruence class with infinitely many elements. Finding b involves solving the Discrete Logarithm Problem).



![alt text](https://github.com/kiranpawar94/cs1653-2020su-haz79-kip28-nic89/blob/phase3_DiffieHellman/reports/Diagram_Threat1_4.png?raw=true)

 

 

### THREAT 2: TOKEN MODIFICATION / FORGERY

THREAT: At the current development stage, the Token class is basically an abstraction for a String which combines the issuer and the subject of a token. After a GET request is successfully processed by the Group Server and a token is issued, the token is stored as a variable in the GUI / CLI application in plaintext without any form of integrity check. Upon any further request, the client attaches this Token to the packet sent to the server for authorization. 

 

EXPLOITATION EXAMPLE: As a plaintext string, the token can be easily modified either by debugging the application with a disassembler to tamper the value during runtime or by intercepting the traffic and modifying the token being sent to the server. 

SECURITY STRATEGIES:  Ensuring Data Integrity using public-key-cryptography (RSA Signatures)

Side effects of Threat 1 security strategies : Since an encryption protocol is initiated, traffic could be supposed to be secure between Client and Server, and an attacker should not be able to inject custom tokens in requests. 

Remaining problem:  The Token class does not implement any obfuscation methods or integrity checks  for its attributes. Therefore, even though an attacker doesn’t know exactly HOW the data is transmitted, the attacker still knows WHAT data the program is working with during execution and can modify it to alter the token BEFORE client-side encryption is applied. 

Providing Data Integrity:  To ensure a token remains intact after the Group Server issues it, an RSA signature of the token will be the chosen method. In particular, since the token is a short string, the RSA signature should be applied to a digest of the token : 

SHA-256 + RSA-2048 or 1024 is an example of a standard way to apply message signatures. In this case, we chose an SHA-256 Token digest signed with the Server's private key (RSA-2048).

VALIDITY: RSA Signature-Verification ensure Data Integrity

Let’s suppose the encryption strategy is broken, by a lucky attacker who guesses the shared key between the client and the Group Server. In fact, tokens are also used for authorization between Clients and the File Server, where we haven’t provided a measure for secure traffic yet. By Signing a Token with the Group Server’s PRIVATE key, and given that its PUBLIC key is available to any principal, anyone can verify whether a token is original. Therefore, both the Group Server and the File Server will be able to check validity of a token provided by the user alongside a request.

 
![alt text](https://github.com/kiranpawar94/cs1653-2020su-haz79-kip28-nic89/blob/phase3_DiffieHellman/reports/Diagram_Threat2.png?raw=true)

### THREAT 3: UNAUTHORIZED FILE SERVERS 

THREAT: At the current development stage, users connect to a File Server by manually specifying the HOST and PORT. This implies some kind of public knowledge that clients need in order to communicate. Therefore, attackers should be supposed to know this information as well. The users have no way of authenticating the File Server. Uploads simply require the source and destination paths, a group to which the user belongs and a valid token, no further confirmation needed from the user. Downloads are also not checked for integrity or malicious content by the application. 

EXPLOITATION EXAMPLE 

Attracting a victim to the fake server: 

The attacker knows the common File Server Port: 4321. A malicious user can run a server with this port open for connections and promote it as a legit File Server.  

Outgoing connections from a client’s computer can be redirected by DNS association rules in the HOSTS system file to any chosen address without the user noticing (PHARMING). 

Once the victim is connected: 

Files can be stolen: The attacker, in control of the victim’s computer, can just list all files and send them over to the fake server without the user noticing by replicating legitimate upload packets. 

Downloads of malware can be forced, or any legit download request can be replied to with the same malware masked as the correct file.  

SECURITY STRATEGIES : File Server public-key-based authentication

In a similar fashion to clients' authentication by the server, the client will receive a public key from the File Server upon the first connection. This key will be sent alongside its digest signed by the File Server, to ensure data integrity.
During the first connection, the Client will assume the File Server is trustworthy.
Upon following connections, the client will compare the public key received with the one it has stored and associated with that File Server. If the keys match, the client will proceed with the connection.

From this moment, the Client and the Server will agree on a shared secret to initiate an encrypted communication using AES-256, in a similar fashion as Threat 1 describes. However, in this case the File Server cannot authenticate the Client, since the Group Server is the principal in charge of that. Therefore, the Diffie-Hellman exchange will be signed only on the File Server's side for the Client to authenticate.

If the Client were to be impersonated during the Diffie-Hellman exchange, an attacker would not be able to get a valid response from the File Server : File operations require a token, which a Server only issues to authenticated Clients.

VALIDITY: RSA signatures for Integrity 

Let’s suppose a Client is successfully tricked into attempting to connect to a fake File Server 

Upon connection, the Client receives a public key from the server along with its digest signed with the server's private key.

The client also computes the received key's digest and compares it with the signed digest received from the server, which is verified using the server's public key.  If the digests don't match, the Client stops the connection.
If the digests match, the client compares the public key against the one stored previously for that server. If they don't match, the client stops the connection.

Properly authenticated File Servers are not malicious, according to the current Trust Model. 


 
![alt text](https://github.com/kiranpawar94/cs1653-2020su-haz79-kip28-nic89/blob/phase3_DiffieHellman/reports/Diagram_Threat3_4.png?raw=true)

### THREAT 4: INFORMATION LEAKAGE via PASSIVE MONITORING 

 

For threat 4 to be implemented correctly, we need encryption. For encryption to be of any use, the parties need to share a secret through an insecure channel. This key-agreement needs authentication. 
Therefore, this threat naturally follows the authentication methods described for Threat 1 and 3, where the encryption is initialized right after authentication. 
This threat is therefore tackled as described in Threats 1 and 3, with their corresponding diagrams.


