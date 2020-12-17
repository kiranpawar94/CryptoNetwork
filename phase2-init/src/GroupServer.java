/* Group server. Server loads the users from UserList.bin.
 * If user list does not exists, it creates a new list and makes the user the server administrator.
 * On exit, the server saves the user list to file. 
 */

/*
 * TODO: This file will need to be modified to save state related to
 *       groups that are created in the system
 *
 */

import java.net.ServerSocket;
import java.net.Socket;
import java.io.*;
import java.util.*;


public class GroupServer extends Server {

	public static final int SERVER_PORT = 8765;
	public UserList userList;
	public GroupList groupList;
    public Crypto.RSA RSAProvider;
    public Crypto.SHA256 DigestProvider;
    public Crypto.AES AESProvider;
	public GroupServer() {
		super(SERVER_PORT, "ALPHA");
	}
	
	public GroupServer(int _port) {
		super(_port, "ALPHA");
	}
	
	public void start() {
		// Overwrote server.start() because if no user file exists, initial admin account needs to be created
		String userFile = "UserList.bin";
		Scanner console = new Scanner(System.in);
		ObjectInputStream userStream;
		ObjectInputStream groupStream;
		
		//This runs a thread that saves the lists on program exit
		Runtime runtime = Runtime.getRuntime();
		runtime.addShutdownHook(new ShutDownListener(this));
		
		//Open user file to get user list
		try
		{
			FileInputStream fis = new FileInputStream(userFile);
			userStream = new ObjectInputStream(fis);
			userList = (UserList)userStream.readObject();
			groupList = new GroupList();
			///
			//LOAD GROUPLIST CODE
			///
			ArrayList<String> users = userList.getUserList();
			Iterator<String> itr = users.iterator();
			ArrayList<String> userGroups = new ArrayList<String>();
			ArrayList<String> userOwnership = new ArrayList<String>();
			while(itr.hasNext()) {
				String currentUser = itr.next();
				userGroups = userList.getUserGroups(currentUser);
				Iterator<String> itr2 = userGroups.iterator();
				while(itr2.hasNext()) {
					String currentGroup = itr2.next();
					
					if (groupList.listGroups().contains(currentGroup)) {
						groupList.addUser(currentUser, currentGroup);
					} else {
						groupList.addGroup(currentGroup);
						groupList.addUser(currentUser, currentGroup);
						
					}
				}
				
				userOwnership = userList.getUserOwnership(currentUser);
				Iterator<String> itr3 = userOwnership.iterator();
				while(itr3.hasNext()) {
					String currentGroup = itr3.next();
					if (groupList.listGroups().contains(currentGroup)) {
						groupList.addOwner(currentUser, currentGroup);
					} else {
						groupList.addGroup(currentGroup);
						groupList.addOwner(currentUser, currentGroup);
					}
				}
			}
			/// END OF GROUPLIST CODE
			
			
			
		}
		catch(FileNotFoundException e)
		{
			System.out.println("UserList File Does Not Exist. Creating UserList...");
			System.out.println("No users currently exist. Your account will be the administrator.");
			System.out.print("Enter your username: ");
			String username = console.next();
			
			//Create a new list, add current user to the ADMIN group. They now own the ADMIN group.
			userList = new UserList();
			groupList = new GroupList();
			userList.addUser(username);
			userList.addGroup(username, "ADMIN");
			userList.addOwnership(username, "ADMIN");
			groupList.addGroup("ADMIN", new ArrayList<String>(Arrays.asList(username)), new ArrayList<String>(Arrays.asList(username)));
			System.out.println(groupList.listGroupUsers("ADMIN").toString());
		}
		catch(IOException e)
		{
			System.out.println("Error reading from UserList file");
			System.exit(-1);
		}
		catch(ClassNotFoundException e)
		{
			System.out.println("Error reading from UserList file");
			System.exit(-1);
		}
		
		//Autosave Daemon. Saves lists every 5 minutes
		AutoSave aSave = new AutoSave(this);
		aSave.setDaemon(true);
		aSave.start();
		
		//Setup RSA
		if(this.setupRSA()) {
			System.out.println("RSA engine initialized successfully");
		
		
		//This block listens for connections and creates threads on new connections
			try
			{
			
				final ServerSocket serverSock = new ServerSocket(port);
			
				Socket sock = null;
				GroupThread thread = null;
				
				while(true)
				{
					sock = serverSock.accept();
					thread = new GroupThread(sock, this);
					thread.start();
				}
			}
			catch(Exception e)
			{
				System.err.println("Error: " + e.getMessage());
				e.printStackTrace(System.err);
			}
		}else {
			System.out.println("Couldn't initialize RSA engine. The server cannot proceed");
		}

	}
	
	public boolean setupRSA() {
		Crypto crypto = new Crypto();
		RSAProvider = crypto.new RSA();
		DigestProvider = crypto.new SHA256();
		try {
			File fpub = new File("pubkey");
			File fpriv = new File("privkey");
			if (!(fpub.exists() && fpriv.exists())) {
				System.out.println("\nRSA Keypair not found. Generating RSA keys and storing them in files named \"pubkey\" and \"privkey\" for the public and private keys, respectively");
				RSAProvider.generateRSAKeys();
			} else {
				System.out.println("\nRSA Keypair found in files named \"pubkey\" and \"privkey\" for the public and private keys, respectively");
				
			}
			
			return true;
		} catch(Exception e) {
			System.err.println("Error generating RSA keys for the Group Server: " + e.getMessage());
			e.printStackTrace(System.err);
		}
		return false;
	}
	
}

//This thread saves the user list
class ShutDownListener extends Thread
{
	public GroupServer my_gs;
	
	public ShutDownListener (GroupServer _gs) {
		my_gs = _gs;
	}
	
	public void run()
	{
		System.out.println("Shutting down server");
		ObjectOutputStream outStream;
		try
		{
			outStream = new ObjectOutputStream(new FileOutputStream("UserList.bin"));
			outStream.writeObject(my_gs.userList);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
}

class AutoSave extends Thread
{
	public GroupServer my_gs;
	
	public AutoSave (GroupServer _gs) {
		my_gs = _gs;
	}
	
	public void run()
	{
		do
		{
			try
			{
				Thread.sleep(300000); //Save group and user lists every 5 minutes
				System.out.println("Autosave group and user lists...");
				ObjectOutputStream outStream;
				try
				{
					outStream = new ObjectOutputStream(new FileOutputStream("UserList.bin"));
					outStream.writeObject(my_gs.userList);
				}
				catch(Exception e)
				{
					System.err.println("Error: " + e.getMessage());
					e.printStackTrace(System.err);
				}
			}
			catch(Exception e)
			{
				System.out.println("Autosave Interrupted");
			}
		}while(true);
	}
}
