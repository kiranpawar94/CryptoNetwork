# Extra Credit PHASE 2
## Graphical User Interface
  - Added a GUI for the Client Application (ClientAppGUI.java) using Java's Swing and AWT libraries
  - ClientApp.java was designed with this in mind, so it was just a matter of linking buttons to functions and redirecting the stdout to a JTextArea
  - The main challenge was to come up with an efficient use of the space to provide a reasonably good UX
  
### Compilation and Usage Instructions
  - javac ClientAppGUI.java // compile the GUI program
  - java ClientApp.java //run the GUI program
  - follow the instructions in usage.md, using the GUI to facilitate the workflow without having to type-in commands in the command line.
  
  # Extra Credit PHASE 3
  
  All the threats addressed for Phase 3 have been approached as if an Active Attacker was monitoring the network and was capable of altering the traffic.
  Therefore, the Authentication and Encryption protocols  take into account the possibility of a MITM trying to establish, for example, two simultaneous Diffie-Hellman handshakes with the client and the server in a way that the attacker would present its own public exponent to the client and share a secret with the client, and the same attacker would present another (or the same) public exponent to the server to establish a different shared secret. This way, an attacker could decrypt, modify and re-encrypt all the traffic going in both directions. 
  
  This is tackled by using public-key-cryptography schemes for authenticating the parties during the Diffie Hellman exchange. The signed key-agreement algorithm makes it possible for the parties to authenticate each other and detect such MITM attempts, as long as that the private keys of both Client and Server remain secret.

Each threat model is explained in more detail in the writeup document describing examples of exploitation for each scenario where active attackers are considered.
