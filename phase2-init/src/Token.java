
import java.util.*;
public class Token implements UserToken, java.io.Serializable {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private String subject;
	private String issuer;
	private List<String> groups;
	private List<String> groupKeys;
	private String signature;
	private String fileServerName;
/*
 * //Issue a new token with server's name, user's name, and user's groups
			*/
	
	public Token(String servername, String username, List<String> userGroups, List<String> groupKeys, String signature, String fileServerName) {
		subject = username;
		issuer = servername;
		groups = userGroups;
		this.groupKeys = groupKeys;
		this.signature = signature;
		this.fileServerName = fileServerName;
	}
	
	public String getSubject() {
		return subject;
	}
	
	public String getIssuer() {
		return issuer;
	}
	/////////////
	public void setIssuer(String issuer) {
		this.issuer = issuer;
	}
	//////////////
	public List<String> getGroups(){
		return groups;
	}
	public List<String> getGroupKeys(){
		return groupKeys;
	}
	public String getGroupKey(String groupname) {
		return groupKeys.get(groups.indexOf(groupname));
	}
	
	public String getSignature() {
		return signature;
	}

	public String getFileServerName() {
		return fileServerName;
	}
}