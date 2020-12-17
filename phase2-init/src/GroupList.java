import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

	public class GroupList implements java.io.Serializable{

		/**
		 * 
		 */
		private static final long serialVersionUID = -3640596306597345734L;
		private Hashtable<String, Group> groupList;
		
		public GroupList() {
			groupList = new Hashtable<String, Group>();
		}
		public synchronized ArrayList<String> listGroups(){
			Set<String> groupnames = groupList.keySet();
			ArrayList<String> groups = new ArrayList<String>();
			groups.addAll(groupnames);
			return groups;
		}
		public synchronized boolean addGroup(String groupname) {
			if (!(groupList.containsKey(groupname))) {
				Group group = new Group(groupname);
				groupList.put(groupname, group);
				return true;
			} else {
				return false; //group already exists
			}
		}
		public synchronized boolean addGroup(String groupname, ArrayList<String> users, ArrayList<String> owners) {

			if (!(groupList.containsKey(groupname))) {
				System.out.println("GroupList.addGroup: group not in list yet. Put successfully");
				Group group = new Group(groupname, users, owners);
				groupList.put(groupname, group);
				return true;
			} else {
				System.out.println("GroupList.addGroup: Group already exists:");
				return false; //group already exists
			}
		}
		public synchronized ArrayList<String> listGroupUsers(String groupname){
			return groupList.get(groupname).getUsers();
		}
		public synchronized ArrayList<String> listGroupOwners(String groupname){
			return groupList.get(groupname).getOwners();
		}
		public synchronized boolean addUser(String username, String groupname){
			System.out.println("Call to GroupList.adduser : " + username + " to "  + groupname);
			if (groupList.containsKey(groupname)){
				System.out.println("Group found in grouplist");
				Group group = groupList.get(groupname);
				
				if(!(group.getUsers().contains(username))) {
					System.out.println("User added");
					group.addUser(username);
					return true;
				} else {
					System.out.println("User already in group");
					return false; //user already in group
				}
			}else {
				System.out.println("GroupList.adduser: group doesnt exist");
				return false; //group doesn't exist
			}
		}
		public synchronized boolean addOwner(String username, String groupname){
			if (groupList.containsKey(groupname)){
				Group group = groupList.get(groupname);
				
				if(!(group.getOwners().contains(username))) {
					group.addOwner(username);
					if(!(group.getUsers().contains(username))){
						group.addUser(username);
					}
					return true;
				} else {
					return false; //user already in group
				}
			}else {
				return false; //group doesn't exist
			}
		}
		
		public synchronized boolean removeUser(String groupname, String username) {
			if (groupList.containsKey(groupname)){
				Group group = groupList.get(groupname);
				
				if((group.getUsers().contains(username))) {
					group.removeUser(username);
					group.updateCurrentKey();
					return true;
				} else {
					return false; //user not in group
				}
			}else {
				return false; //group doesn't exist
			}
		}
		public synchronized boolean removeOwner(String groupname, String username) {
			//don't call updateCurrentKey here on the group, it's done when deleting owner from users
			if (groupList.containsKey(groupname)){
				Group group = groupList.get(groupname);
				
				if((group.getOwners().contains(username))) {
					group.removeOwner(username);
					return true;
				} else {
					return false; //user not an owner
				}
			}else {
				return false; //group doesn't exist
			}
		}
		public synchronized boolean deleteGroup(String groupname) {
			if (groupList.containsKey(groupname)) {

				groupList.get(groupname).removeKeyFile();
				groupList.remove(groupname);
				return true;
			}else {
				return false; // group doesn't exist
			}
		}
		
		public synchronized boolean updateGroupKey(String groupname) {
			if(groupList.get(groupname).updateCurrentKey()) {
				System.out.println("Group " + groupname + "'s key successfully updated");
				return true;
			}
			return false;
		}
		public synchronized boolean removeKeyFile(String groupname) {
			if(groupList.get(groupname).removeKeyFile()) {
				System.out.println("Group " + groupname + "'s key file successfully deleted");
				return true;
			}
			return false;
		}
		public synchronized String getGroupKey(String groupname) {
			if (groupList.containsKey(groupname)){
				Group group = groupList.get(groupname);
				return group.getGroupKey() + "__HASHINDEX__=" + group.currentKey;
				
			}else {
				return null; //group doesn't exist
			}
		}

	}
	
	class Group implements java.io.Serializable{

		/**
		 * 
		 */
		private static final int MAX_USER_REMOVALS = 20;
		private static final long serialVersionUID = -1373528574759055835L;
		private ArrayList<String> users;
		private ArrayList<String> owners;
		private String name;
		public Crypto.SHA256 DigestProvider;
		private Hashtable<Integer, String> reverseHashChain;
		public int currentKey;
		public Group(String groupname) {
			name = groupname;
			users = new ArrayList<String>();
			owners = new ArrayList<String>();
			reverseHashChain = new Hashtable<Integer,String>();
			Crypto crypto = new Crypto();
			DigestProvider = crypto.new SHA256();
			if(loadReverseHashChain()) {
				System.out.println("Group " + name + "'s reverse hash chain of keys loaded successfully");
				System.out.println("Group " + name + "'s current key index: " + currentKey);

			}

			
		}
		public Group(String groupname, ArrayList<String> users, ArrayList<String> owners) {
			name = groupname;
			this.users = users;
			this.owners = owners;
			reverseHashChain = new Hashtable<Integer,String>();
			Crypto crypto = new Crypto();
			DigestProvider = crypto.new SHA256();
			
			if(loadReverseHashChain()) {
				System.out.println("Group " + name + "'s reverse hash chain of keys loaded successfully");
				System.out.println("Group " + name + "'s current key index: " + currentKey);

				
			}
		}
		public ArrayList<String> getUsers(){
			return users;
		}
		public ArrayList<String> getOwners(){
			return owners;
		}
		public boolean addUser(String username){
			if(users.contains(username)) {
				return false; //user already in group
			}
			users.add(username);
			return true;
		}
		public boolean addOwner(String username) {
			if(owners.contains(username)) {
				return false; //user already an admin
			}
			if(!(users.contains(username))) {
				users.add(username);
			}
			owners.add(username);
			return true;
		}
		public boolean removeUser(String username) {
			if(users.contains(username)) {
				users.remove(username);
				if(owners.contains(username)) {
					owners.remove(username); //if user removed from group, automatically remove from owners
				}
				return true;
			} else {
				return false; //user not in group
			}
		}
		public boolean removeOwner(String username) {
			if(owners.contains(username)) {
				owners.remove(username);
				return true;
			} else {
				return false; //user not an owner
			}
		}
		public String getGroupKey() {
			return reverseHashChain.get(currentKey);
		}
		private boolean loadReverseHashChain() {
			try {
				
				File tmpDir = new File("." + File.separator + "groups_keys");
				//CHECK DIRECTORY EXISTS
				if(tmpDir.exists() && tmpDir.isDirectory()) {
					System.out.println("\n\n\t/groups_keys found");
					//CHECK IF KEY IS ALREADY STORED
					File tmpFile = new File("." + File.separator + "groups_keys" + File.separator + name + "_key");
					if(tmpFile.exists() && tmpFile.isFile()) {
						return retrieveReverseHashChain();
					
					}else { // NEW GROUP

						return computeReverseHashChain();
					}
				}else {
					//FIRST GROUP EVER IN SERVER -> CREATE DIRECTORY AND STORE KEYS
					if(tmpDir.mkdir()) {
						return computeReverseHashChain();
					}else {
						return false; // couldn't create directory
					}
				}
			} catch (Exception e) {
				return false;
			}
			
		}
		
		private boolean computeReverseHashChain() {
			try {
				Random rnd = new Random();
				int Kn = rnd.nextInt(MAX_USER_REMOVALS) + MAX_USER_REMOVALS;
				int seed = rnd.nextInt(); // random seed to generate first key of reverse hash chain
				String prevKey = DigestProvider.messageDigest(String.valueOf(seed)); //store computed hashes so we don't have to access the hashtable
				
				
				reverseHashChain.put(Kn, prevKey);
				
				
				File tmpFile = new File("." + File.separator + "groups_keys" + File.separator + name + "_key");
				if(tmpFile.createNewFile()) {
					FileWriter myWriter = new FileWriter("." + File.separator + "groups_keys" + File.separator + name + "_key");
					myWriter.write("*CurrentKey=0\n");
					currentKey = 0;
					myWriter.write(String.valueOf(Kn) + "," + prevKey + "\n");
					for(int i = Kn - 1; i >= 0; i--) {
						prevKey = DigestProvider.messageDigest(prevKey);
						reverseHashChain.put(i, prevKey);
						myWriter.write(String.valueOf(i) + "," + prevKey + "\n");
					}
					
					myWriter.close();	
					System.out.println("Successfully computed and stored group " + name + "'s reverse hash chain of keys");
					return true;
				}
				return false;
				
			} catch (Exception e) {
				return false;
			}
			
			
		}
		
		
		private boolean retrieveReverseHashChain() {
			try {
					File tmpFile = new File("." + File.separator + "groups_keys" + File.separator + name + "_key");
					FileInputStream fis=new FileInputStream(tmpFile);       
					Scanner sc=new Scanner(fis);    //file to be scanned  
					//returns true if there is another line to read  
					String line;
					while(sc.hasNextLine())  
					{  
						line = sc.nextLine();      //returns the line that was skipped 

						if(line.contains("*CurrentKey=")) {
							currentKey = Integer.parseInt(line.split("=")[1]);
						}else {

							reverseHashChain.put(Integer.parseInt(line.split(",")[0]), line.split(",")[1]);
						}
					}  
					sc.close();
					return true;
				} catch (Exception e) {
					return false;
				}
			
		}
		public boolean updateCurrentKey() {
			try {
				 Path filePath = Paths.get("." + File.separator + "groups_keys" + File.separator + name + "_key");
				 List<String> lines = Files.readAllLines(filePath);
				 int nextKey = Integer.parseInt(lines.get(0).split("=")[1]) + 1;
				 if(nextKey >= lines.size() - 1) {//last key reached
					 System.out.println("Last pre-computed key reached. The sysadmin should generate more keys from scratch, re-encrypt all previous files and update their key tags");
					 return false;
				 }
				 System.out.println("Group " + name + "'s current key: " + nextKey);
				 currentKey = nextKey;
				 lines.set(0, lines.get(0).split("=")[0] + "=" + nextKey);
				 Files.write(filePath, lines);
				 return true;
			} catch (Exception e) {
				return false;
			}
			
		}
		public boolean removeKeyFile() {
			try {
				File tmpFile = new File("." + File.separator + "groups_keys" + File.separator + name + "_key");
				if(tmpFile.delete()) {
					return true;
				}
				return false;
			} catch (Exception e) {
				return false;
			}
		}
	}
