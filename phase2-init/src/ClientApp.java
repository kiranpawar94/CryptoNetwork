import java.util.List;
import java.util.Scanner;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.util.Iterator;


public class ClientApp {
	private FileClient fileclient;
	private GroupClient groupclient;
	private CLInterface cli;
	
	private UserToken currentToken;
	
	private boolean stdout;
	
	
	
	public ClientApp() { // NON GUI CONSTRUCTOR
		fileclient = new FileClient();
		groupclient = new GroupClient();
		currentToken = null;
		cli = new CLInterface();
		stdout = true; // std output
	}
	
	public ClientApp(boolean stdout) { //GUI CONSTRUCTOR
		fileclient = new FileClient();
		groupclient = new GroupClient();
		currentToken = null;
		cli = new CLInterface();
		this.stdout = stdout;
		
		 
		
		
	}
	
	
	
	
	
	public boolean connectGroupClient(String server, int port) {
		//sanitize input
		if (groupclient.connect(server,  port)) {
			print("Group client connected to address : " + server + ":" + Integer.toString(port), stdout);
			
			
			return true;
		}
		print("Error while connecting group client to address : " + server + ":" + Integer.toString(port), stdout);
		return false ;
	}
	
	public void disconnectGroupClient() {
		groupclient.disconnect();
		currentToken = null;
	}
	public void getToken(String username, String fileServerName) {
		// disconnect from servers if the token is changed
		if (groupclient.isConnected() == false) {
			System.out.println("Connect to the group server before requesting a token");
			return;
		}
		if (currentToken != null) {
			System.out.println("Disconnect from the server before changing the token");
			return;
		}
		if (fileclient.isConnected()) disconnectFileClient();
		UserToken t = groupclient.getToken(username, fileServerName);
		if(t!= null) {
			currentToken = t;
			print(t.getIssuer() + " granted token to user " + t.getSubject(), stdout);
		}
		return;
	}
	public void createUser(String username) {
		boolean success = groupclient.createUser(username, currentToken);
		if(success) {
			print("User " + username + " successfully created", stdout);
		} else {
			print("Error encountered while creating user", stdout);
		}
		return;
	}
	public void deleteUser(String username) {
		boolean success = groupclient.deleteUser(username,  currentToken);
		if(success) {
			print("User " + username + " successfully deleted", stdout);
		} else {
			print("Error encountered while deleting user", stdout);
		}
		return ;

	}
	public void createGroup( String groupname) {
		boolean success = groupclient.createGroup(groupname, currentToken);
		if(success) {
			print("Group " + groupname + " successfully created", stdout);
		} else {
			print("Error encountered while creating group", stdout);
		}
		return ;
	}
	public void deleteGroup( String groupname) {
		boolean success =  groupclient.deleteGroup(groupname,  currentToken);
		if(success) {
			print("Group " + groupname + " successfully deleted", stdout);
		} else {
			print("Error encountered while deleting group", stdout);
		}
		return;
	}
	public void addUserToGroup( String user,  String group) {
		boolean success =  groupclient.addUserToGroup(user, group, currentToken);
		if(success) {
			print("User " + user + " added to group " + group + " successfully", stdout);
		} else {
			print("Error encountered while adding user" + user + "to group " + group, stdout);
		}
		return ;
	}
    public void deleteUserFromGroup( String user,  String group) {
    	boolean success = groupclient.deleteUserFromGroup(  user,  group,   currentToken);
		if(success) {
			print("User" + user + " deleted from group " + group + " successfully", stdout);
		} else {
			print("Error encountered while deleting user", stdout);
		}
    	return;
    }
    public void listGroupMembers( String group){
    	if(currentToken == null) {
    		print("You need a session token to be authorized. Type in --help for instructions.", stdout);
    	}
    	List<String> ls =  groupclient.listMembers(  group,   currentToken);
		if(ls != null) {
			//System.out.println(ls.size());
			Iterator<String> itr = ls.iterator();
			print("Listing " + group + "'s members :", stdout);
			while(itr.hasNext()) {
				print("\t " + itr.next(), stdout);
			}
		} else {
			print("Error encountered while listing group " + group + "'s members", stdout);
		}
    	return;
    }
	
	public static void print(String str, boolean cli) {
		if(cli == true) {
			System.out.println(str);
		}
	}
	
	
	
	
	public boolean connectFileClient(String server, int port) {
		//sanitize input
		System.out.println(((Token)currentToken).getFileServerName());
		System.out.println(server + ":" + String.valueOf(port));
		
		if(!(((Token)currentToken).getFileServerName().equals(server + ":" + String.valueOf(port)))){
			print("Security error: The current token is not valid for the requested server", stdout);
			return false;
		}
		
		if ( fileclient.connect(server,  port)) {
			if(handshakeDH()) {
			print("File client connected to address : " + server + ":" + Integer.toString(port), stdout);
			return true;
			}
		}
		
		print("Error while connecting file server to address : " + server + ":" + Integer.toString(port), stdout);
		return false ;
		
	}
	public void disconnectFileClient() {
		fileclient.disconnect();
	}
	
	public void listFiles(){
		if (currentToken == null) {
			System.out.println("A valid token is required to list files");
			return;
		}
		List<String> result = fileclient.listFiles(currentToken);
		if(result != null && result.size() > 0) {
			print("List of files accessible to user ",  true);
			for(String s : result) {
				print("\t" + s, stdout);
			}
		}
		//check token 
		return ;
	}

	public boolean handshakeDH() {
		if (currentToken == null) {
			System.out.println("A valid token is required to connect to file server");
			return false;
		}
		boolean result = fileclient.doHandshakeDH(currentToken.getSubject());
		if(result) {
			print("DH handshake is completed successfully", stdout);
		} else {
			print("DH handshake fails", stdout);
		}
		return result;		
	}
	
    public boolean uploadFile(String sourceFile, String destFile, String group) {    	
    	//  List<String> userGroups = currentToken.getGroups();//NOT NEEDED?
    	//  if(sourceFile == null || destFile == null || group == null) {
    	// 	 print("Error uploading file: Fill in all parameters.", stdout);
    	// 	 return false;
    	//  }
    	//  boolean userInGroup = groupclient.listMembers(group, currentToken).contains(currentToken.getSubject());
    	//  if(userInGroup) {
    	// 	 if (fileclient.upload(sourceFile, destFile, group, currentToken)){
    	//         	print("File " + sourceFile + " uploaded as " + destFile, stdout);
    	//         	return true;
    	//     	} else {
    	//     		print("Error uploading file " + sourceFile, stdout);
    	//     		return false; // error downloading
    	//     	}
    		
    	// } else {
    	// 	print("Permission denied: current user " + currentToken.getSubject() + " not found in group " + group, stdout);
    	// 	return false;//user not in group
    	// }
		if (fileclient.upload(sourceFile, destFile, group, currentToken)){
			print("File " + sourceFile + " uploaded as " + destFile, stdout);
    	    return true;
    	} else {
    	    print("Error uploading file " + sourceFile, stdout);
    	    return false; // error downloading
    	}
    }
    
    public boolean downloadFile(String sourceFile, String destFile) {
    	if (fileclient.download(sourceFile, destFile, currentToken)){
        	print("File " + sourceFile + " downloaded as " + destFile, stdout);
        	return true;
    	} else {
    		print("Error downloading file " + sourceFile, stdout);
    		return false;
    	}
    }
    
    public boolean deleteFile(String filename) {
    	if (fileclient.listFiles(currentToken).contains(filename) || fileclient.listFiles(currentToken).contains("/" + filename)){
    		
    		if(fileclient.delete(filename, currentToken)) {
    			//print("File " + filename + " deleted", stdout);
    			return true;
    		} else if (filename.charAt(0) != '/' && (fileclient.delete("/" + filename, currentToken)) ) {
    			print("File " + filename + " deleted", stdout);
    			return true;
    		} else {
    			//print("Error deleting file " + filename, stdout);
    			return false; //couldnt delete
    		}
    	} else {
    		print("File " + filename + " not found among current user " + currentToken.getSubject() + "'s files", stdout );
    		return false; //no permissions
    	}
    }
    
    private class CLInterface{
		public CLInterface() {}
		public void parseArgs(String[] args) {
			
		}
		public void printHelp() {
			print("\n"
					+ "************************\n\tUSAGE\n**************************\n"
					+ "Arguments:"
					
					+ "\n\t -g [GroupClient_Function]"
					
					+ "\n\t\t GroupClient_Functions:"
					
					+ "\n\t\t\t connect \"server\" \"port\""
					+ "\n\t\t\t disconnect"
					+ "\n\t\t\t getToken \"username\" \"fileServerName\""
					+ "\n\t\t\t\t * This sets the current user token, which will be used for any further operations"
					+ "\n\t\t\t\t * Get a new token by repeating this command with a different user to change the current token"
					+ "\n\t\t\t createUser \"username\""
					+ "\n\t\t\t deleteUser \"username\""
					+ "\n\t\t\t createGroup \"group\""
					+ "\n\t\t\t deleteGroup \"group\""
					+ "\n\t\t\t addUserToGroup \"username\" \"group\""
					+ "\n\t\t\t deleteUserFromGroup \"username\" \"group\""
					+ "\n\t\t\t listGroupMembers \"group\""
					
					+ "\n\t -f [FileClient_Function]"
					
					+ "\n\t\t FileClient_Functions:"
					
					+ "\n\t\t\t connect \"server\" \"port\""
					+ "\n\t\t\t disconnect"
					+ "\n\t\t\t listFiles"
					+ "\n\t\t\t uploadFile \"sourceFile\" \"destFile\" \"group\""
					+ "\n\t\t\t\t * You will need to be logged into a GroupServer to perform this action"
					+ "\n\t\t\t\t * 1: Connect to a GroupServer typing -g connect \"server\" \"port\""
					+ "\n\t\t\t\t * 2: Get a Token by typing -g getToken \"username\" \"fileServerName\""
					
					+ "\n\t\t\t downloadFile \"sourceFile\" \"destFile\""
					+ "\n\t\t\t deleteFile \"filename\""
					+ "\n\t\t\t handshakeDH \"username\"\n"
					+ "Type in a command : "
					, stdout);
		}
	}
	
	public static void main(String[] arglist) {
		ClientApp cl = new ClientApp();
		Scanner command = new Scanner(System.in);

	    print("\n**************************************\n"
	    		+ " WELCOME TO THE Group-based File Server by haz79, kip28 and nic89\n" 
	    		+ 			"**************************************\n"
	    		+ "Here are the instructions to use the Client program. If you need to see them again, just type in -h or --help", true);
	    cl.cli.printHelp();
	    boolean running = true;

	    while(running){
	    	String[] args = command.nextLine().split(" ");
	    	
	        switch(args[0]){
	        
	        case "-g":
	        	
	        	switch(args[1]) {
	        		case "connect":
	        			if(args.length != 4) {
	        				print("Wrong number of arguments\n", true);
	        				break;
	        			}
	        			cl.connectGroupClient(args[2], Integer.parseInt(args[3]));
	        			break;
	        		case "disconnect":
	        			cl.disconnectGroupClient();
	        			break;
	        		case "getToken":
	        			if(args.length != 4) {
	        				print("Wrong number of arguments\\n", true);
	        				break;
	        			}
	        			cl.getToken(args[2], args[3]);
	        			break;
	        		case "createUser":
	        			if(args.length != 3) {
	        				print("Wrong number of arguments\n",true);
	        				break;
	        			}
	        			cl.createUser(args[2]);
	        			break;
	        		case "deleteUser":
	        			if(args.length != 3) {
	        				print("Wrong number of arguments\n", true);
	        				break;
	        			}
	        			cl.deleteUser(args[2]);
	        			break;
	        		case "createGroup":
	        			if(args.length != 3) {
	        				print("Wrong number of arguments\n", true);
	        				break;
	        			}
	        			cl.createGroup(args[2]);
	        			break;
	        		case "deleteGroup":
	        			if(args.length != 3) {
	        				print("Wrong number of arguments\n", true);
	        				break;
	        			}
	        			cl.deleteGroup(args[2]);
	        			break;
	        		case "addUserToGroup":
	        			if(args.length != 4) {
	        				print("Wrong number of arguments\n", true);
	        				break;
	        			}
	        			cl.addUserToGroup(args[2], args[3]);
	        			break;
	        		case "deleteUserFromGroup":
	        			if(args.length != 4) {
	        				print("Wrong number of arguments\n", true);
	        				break;
	        			}
	        			cl.deleteUserFromGroup(args[2], args[3]);
	        			break;
	        		case "listGroupMembers":
	        			if(args.length != 3) {
	        				print("Wrong number of arguments\n", true);
	        				break;
	        			}
	        			cl.listGroupMembers(args[2]);
	        			break;
	        		default:
	        			print("Command not recognized. Type -h or --help for help\nType in a command : ", true);
	        			break;
	        		}
	        	break;
	        	
	        	
	        case "-f":
	        	switch(args[1]) {
	        		case "connect":
	        			if(args.length != 4) {
	        				print("Wrong number of arguments\n", true);
	        				break;
	        			}
	        			cl.connectFileClient(args[2], Integer.parseInt(args[3]));
	        			break;
	        		case "disconnect":
	        			cl.disconnectFileClient();
	        			break;
	        		case "listFiles":
	        			if(args.length != 2) {
	        				print("Wrong number of arguments\n", true);
	        				break;
	        			}
	        			cl.listFiles();
	        			break;
	        		case "uploadFile":
	        			if(args.length != 5) {
	        				print("Wrong number of arguments\n", true);
	        				break;
	        			}
	        			cl.uploadFile(args[2], args[3], args[4]);
	        			break;
	        		case "downloadFile":
	        			if(args.length != 4) {
	        				print("Wrong number of arguments\n", true);
	        				break;
	        			}
	        			cl.downloadFile(args[2], args[3]);
	        			break;
	        		case "deleteFile":
	        			if(args.length != 3) {
	        				print("Wrong number of arguments\n", true);
	        				break;
	        			}
	        			cl.deleteFile(args[2]);
	        			break;
					/*case "handshakeDH":
						if(args.length != 3) {
	        				print("Wrong number of arguments\n", true);
	        				break;
						}
						cl.handshakeDH();
						break;*/
	        		default:
	        			print("Command not recognized. Type -h or --help for help\nType in a command: ", true);
	        			break;
        			}
	        	
	        	break;
	        	
	        	
	        case "exit":
	        	running = false;
	        	break;
	        case "--help":
	        case "-h":
	        	cl.cli.printHelp();

	        default:
	            print("Command not recognized. Type -h or --help for help\nType in a command: ", true);
	            break;
	        }
	    }
	    command.close();
	}
}



	

