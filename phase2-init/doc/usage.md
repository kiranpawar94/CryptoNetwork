
# Usage Instructions

## Before starting to use the program
Make sure to run GroupServer first. This will allow the RSA keypair to be generated so the public key can be distributed to all the other parties out-of-band. In particular, the file "pubkey" should be copied in the root folder of every part of the application run in different machines (same folder as ClientApp.java for clients and smae folder as RunFileServer.java for File Servers).


## Running the Group Server

To start the Group Server:
 - Enter the directory containing `RunGroupServer.class`
 - Type `java -cp .:bcprov-ext-jdk15on-165.jar RunGroupServer [port number]`

Note that the port number argument to `RunGroupServer` is optional.  This argument specifies the port that the Group Server will listen to.  If unspecified, it defaults to port 8765.

When the group server is first started, there are no users or groups. Since there must be an administer of the system, the user is prompted via the console to enter a username. This name becomes the first user and is a member of the *ADMIN* group.  No groups other than *ADMIN* will exist.

## Running the File Server

To start the File Server:
 - Enter the directory containing `RunFileServer.class`
 - Type `java -cp .:bcprov-ext-jdk15on-165.jar RunFileServer [port number]`

Note that the port number argument to `RunFileServer is optional.  This argument speficies the port that the File Server will list to. If unspecified, it defaults to port 4321.

The file server will create a shared_files inside the working directory if one does not exist. The file server is now online.

## Resetting the Group or File Server

To reset the Group Server, delete the file `UserList.bin`

To reset the File Server, delete the `FileList.bin` file and the `shared_files/` directory.

## Running the Client Application in the Console
To start the client:
 - Enter the directory containing `ClientApp.class`
 - Type `java -cp .:bcprov-ext-jdk15on-165.jar ClientApp`
 - Follow the instructions on screen
 - Type "exit" and press Enter to terminate the program

## Example
Suppose that the group server and the file server have been started. The following commands connect to the group server, get the token of the administrator with username 'admin', and create a usuer with username 'Bob':  
- `-g connect localhost 8765`  
- `-g getToken admin`  
- `-g createUser Bob`  
## Example 2
To create a group, add a user to the group, upload a file "file.txt", and download it :
- `-g connect localhost 8765`   
- `-g getToken admin` 
- `-g createGroup MyGroup`  
- `-g addUserToGruop Bob MyGroup` 
- `-g getToken Bob`  // Log in as Bob
- * Place the file "file.txt" in the 'src' folder, or alternatively type in the absolute path to the file as an argument for the command below
- `-f uploadFile file.txt uploadedfile.txt MyGroup` 
- `-f downloadFile uploadedfile.txt downloadedfile.txt` 
