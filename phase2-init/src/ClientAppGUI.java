import java.awt.*;
import javax.swing.*;
import java.awt.event.*;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;

public class ClientAppGUI extends JFrame{
	JFrame f;  
	ClientApp cl;
	
	//only used by GUI
	ByteArrayOutputStream baos;
	
public ClientAppGUI(){  
	//Save old stdout and stderr
	PrintStream standardOut = System.out;
	PrintStream standardErr = System.err;
	
	PrintStream printStream = new PrintStream(new CustomOutputStream(createServerLog()));
	System.setOut(printStream);
	System.setErr(printStream);
	//////////////////////GUI-SPECIFIC CODE 
	/// https://stackoverflow.com/questions/8708342/redirect-console-output-to-string-in-java
	
	
	
	cl = new ClientApp(); // constructor with stdout = false
		
	///////////////////////////// MAIN WINDOW PANEL
	JPanel mainPanel = new JPanel();
	mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.X_AXIS));
	
	///////////////////////////// GROUP SERVER FUNCTIONS PANEL
	JPanel groupPanel = new JPanel();
	groupPanel.setLayout(new BoxLayout(groupPanel, BoxLayout.Y_AXIS));
	
	//GROUP CONNECTION
	JPanel groupConnectPanel = new JPanel();
	groupConnectPanel.setLayout(new FlowLayout());
	
	JLabel lbGroupHost = new JLabel("Connect to Host :");
	JTextField txGroupHost = new JTextField("127.0.0.1");
	txGroupHost.setColumns(10);
	JLabel lbGroupPort = new JLabel(" on Port :");
	JTextField txGroupPort = new JTextField("8765");
	txGroupPort.setColumns(5);
	JButton btGroupConnect = new JButton("Connect");
	JButton btGroupDisconnect = new JButton("Disconnect");
	groupConnectPanel.add(lbGroupHost);	
	groupConnectPanel.add(txGroupHost);
	groupConnectPanel.add(lbGroupPort);
	groupConnectPanel.add(txGroupPort);
	groupConnectPanel.add(btGroupConnect);
	groupConnectPanel.add(btGroupDisconnect);
	
	btGroupConnect.addActionListener(new ActionListener() {
         public void actionPerformed(ActionEvent e) {
            cl.connectGroupClient(txGroupHost.getText(), Integer.parseInt(txGroupPort.getText()));
         }          
      });
	btGroupDisconnect.addActionListener(new ActionListener() {
         public void actionPerformed(ActionEvent e) {
        	 cl.disconnectGroupClient();
         }          
      });
	
	//GROUP USER OPTIONS
	JPanel groupUserPanel = new JPanel();
	groupUserPanel.setLayout(new FlowLayout());
	
	JLabel lbUser = new JLabel("Username:");
	JTextField txUser = new JTextField();
	txUser.setColumns(10);

	JButton btToken = new JButton("Get Token");
	JButton btNewUser = new JButton("Create User");
	JButton btDelUser = new JButton("Delete User");
	
	btToken.addActionListener(new ActionListener() {
        public void actionPerformed(ActionEvent e) {
           cl.getToken(txUser.getText(), txUser.getText());
        }          
     });
	btNewUser.addActionListener(new ActionListener() {
        public void actionPerformed(ActionEvent e) {
       	 cl.createUser(txUser.getText());
        }          
     });
	btDelUser.addActionListener(new ActionListener() {
        public void actionPerformed(ActionEvent e) {
       	 cl.deleteUser(txUser.getText());
        }          
     });

	groupUserPanel.add(lbUser);	
	groupUserPanel.add(txUser);
	groupUserPanel.add(btToken);
	groupUserPanel.add(btNewUser);
	groupUserPanel.add(btDelUser);
	
	//GROUP GROUP OPTIONS
	JPanel groupGroupPanel = new JPanel();
	groupGroupPanel.setLayout(new FlowLayout());
	
	JLabel lbGroup = new JLabel("Group name:");
	JTextField txGroup = new JTextField();
	txGroup.setColumns(10);
	JButton btNewGroup = new JButton("Create Group");
	JButton btDelGroup = new JButton("Delete Group");
	JButton btListGroup = new JButton("List Members");
	btNewGroup.addActionListener(new ActionListener() {
        public void actionPerformed(ActionEvent e) {
       	 cl.createGroup(txGroup.getText());
        }          
     });
	btDelGroup.addActionListener(new ActionListener() {
        public void actionPerformed(ActionEvent e) {
       	 cl.deleteGroup(txGroup.getText());
        }          
     });
	btListGroup.addActionListener(new ActionListener() {
        public void actionPerformed(ActionEvent e) {
       	 cl.listGroupMembers(txGroup.getText());
        }          
     });
	
	
	groupGroupPanel.add(lbGroup);	
	groupGroupPanel.add(txGroup);
	groupGroupPanel.add(btNewGroup);
	groupGroupPanel.add(btDelGroup);
	groupGroupPanel.add(btListGroup);
	
	//GROUP USER-GROUP OPTIONS
	JPanel groupUserGroupPanel = new JPanel();
	groupUserGroupPanel.setLayout(new FlowLayout());
	
	JLabel lbUserGroupName = new JLabel("User name:");
	JTextField txUserGroupName = new JTextField();
	txUserGroupName.setColumns(10);
	JLabel lbUserGroupGroup = new JLabel("Group name:");
	JTextField txUserGroupGroup = new JTextField();
	txUserGroupGroup.setColumns(10);
	
	JButton btAddUserGroup = new JButton("Add User");
	JButton btDelUserGroup = new JButton("Delete User");
	
	btAddUserGroup.addActionListener(new ActionListener() {
        public void actionPerformed(ActionEvent e) {
      
       	 	cl.addUserToGroup(txUserGroupName.getText(), txUserGroupGroup.getText());
        }          
     });
	btDelUserGroup.addActionListener(new ActionListener() {
        public void actionPerformed(ActionEvent e) {
        	
          	 cl.deleteUserFromGroup(txUserGroupName.getText(), txUserGroupGroup.getText());
        }          
     });
	
	groupUserGroupPanel.add(lbUserGroupName);	
	groupUserGroupPanel.add(txUserGroupName);
	groupUserGroupPanel.add(lbUserGroupGroup);	
	groupUserGroupPanel.add(txUserGroupGroup);
	groupUserGroupPanel.add(btAddUserGroup);
	groupUserGroupPanel.add(btDelUserGroup);
	
	
	
	
	groupPanel.add(new JLabel("Group Client"));
	groupPanel.add(groupConnectPanel);	
	groupPanel.add(groupUserPanel);
	groupPanel.add(groupGroupPanel);
	groupPanel.add(groupUserGroupPanel);
	
	
	mainPanel.add(groupPanel);

	
	//////////////////////////// FILE SERVER FUNCTIONS PANEL
	JPanel filePanel = new JPanel();
	filePanel.setLayout(new BoxLayout(filePanel, BoxLayout.Y_AXIS));
	
	//GROUP CONNECTION
	JPanel fileConnectPanel = new JPanel();
	fileConnectPanel.setLayout(new FlowLayout());
	
	JLabel lbFileHost = new JLabel("Connect to Host :");
	JTextField txFileHost = new JTextField("127.0.0.1");
	txFileHost.setColumns(10);
	JLabel lbFilePort = new JLabel(" on Port :");
	JTextField txFilePort = new JTextField("4321");
	txFilePort.setColumns(5);
	JButton btFileConnect = new JButton("Connect");
	JButton btFileDisconnect = new JButton("Disconnect");
	btFileConnect.addActionListener(new ActionListener() {
        public void actionPerformed(ActionEvent e) {
       	 	cl.connectFileClient(txFileHost.getText(), Integer.parseInt(txFilePort.getText()));
        }          
     });
	btFileDisconnect.addActionListener(new ActionListener() {
        public void actionPerformed(ActionEvent e) {
          	 cl.disconnectFileClient();
        }          
     });
	
	fileConnectPanel.add(lbFileHost);	
	fileConnectPanel.add(txFileHost);
	fileConnectPanel.add(lbFilePort);
	fileConnectPanel.add(txFilePort);
	fileConnectPanel.add(btFileConnect);
	fileConnectPanel.add(btFileDisconnect);
	
	//FILE LIST OPTION
	JPanel fileListPanel = new JPanel();
	fileListPanel.setLayout(new FlowLayout());
	
	JLabel lbFileList = new JLabel("User name:");
	JTextField txFileList = new JTextField();
	txFileList.setColumns(10);
	JButton btFileList = new JButton("List user's Files");
	fileListPanel.add(lbFileList);	
	fileListPanel.add(txFileList);
	fileListPanel.add(btFileList);
	btFileList.addActionListener(new ActionListener() {
        public void actionPerformed(ActionEvent e) {
       	 	cl.listFiles();
        }          
     });
	
	
	
	//FILE UPLOAD-DOWNLOAD OPTION
		JPanel fileUpPanel = new JPanel();
		fileUpPanel.setLayout(new FlowLayout());
		
		JPanel fileDownPanel = new JPanel();
		fileDownPanel.setLayout(new FlowLayout());
		
		JLabel lbFileSource = new JLabel("Source File:");
		JTextField txFileSource = new JTextField();
		txFileSource.setColumns(10);
		
		JLabel lbFileDest = new JLabel("Destination File:");
		JTextField txFileDest = new JTextField();
		txFileDest.setColumns(10);
		JLabel lbFileGroup = new JLabel("Group (Upload only):");
		JTextField txFileGroup = new JTextField();
		txFileGroup.setColumns(10);
		
		JButton btFileDownload = new JButton("Download File");
		JButton btFileUpload = new JButton("Upload File");
		btFileDownload.addActionListener(new ActionListener() {
	        public void actionPerformed(ActionEvent e) {
	       	 	cl.downloadFile(txFileSource.getText(), txFileDest.getText());
	        }          
	     });
		btFileUpload.addActionListener(new ActionListener() {
	        public void actionPerformed(ActionEvent e) {
	          	 cl.uploadFile(txFileSource.getText(), txFileDest.getText(), txFileGroup.getText());
	        }          
	     });
		
		
		fileUpPanel.add(lbFileSource);	
		fileUpPanel.add(txFileSource);
		fileUpPanel.add(lbFileGroup);	
		fileUpPanel.add(txFileGroup);
		fileUpPanel.add(lbFileDest);	
		fileUpPanel.add(txFileDest);
		
		fileDownPanel.add(btFileUpload);
		fileDownPanel.add(btFileDownload);
		
		//FILE DELETE OPTION
		JPanel fileDelPanel = new JPanel();
		fileDelPanel.setLayout(new FlowLayout());
		
		JLabel lbFileDel = new JLabel("File name:");
		JTextField txFileDel = new JTextField();
		txFileDel.setColumns(10);
		JButton btFileDel = new JButton("Delete File");
		fileDelPanel.add(lbFileDel);	
		fileDelPanel.add(txFileDel);
		fileDelPanel.add(btFileDel);
		btFileDel.addActionListener(new ActionListener() {
	        public void actionPerformed(ActionEvent e) {
	          	 cl.deleteFile(txFileDel.getText());
	        }          
	     });
	
	filePanel.add(new JLabel("File Client"));
	filePanel.add(fileConnectPanel);
	filePanel.add(fileListPanel);
	filePanel.add(fileUpPanel);
	filePanel.add(fileDownPanel);

	filePanel.add(fileDelPanel);
	
	
	mainPanel.add(filePanel);
	
	//Set up main window    
	add(mainPanel);
	//setSize(800,900);
	setVisible(true); 
	pack();
	
	addWindowListener(new WindowAdapter() {
	 
	@Override
	 
	public void windowClosing(WindowEvent e) {
		System.setOut(standardOut);
		System.setErr(standardErr);
	    System.exit(0);
	 
	}
	 
	  });
	
	}  
	
	private JTextArea createServerLog() {
		JFrame log = new JFrame();
		//log.setLayout(new BoxLayout(log, BoxLayout.X_AXIS));
		
		JTextArea console = new JTextArea("\n"
				+ "************************\nHELP NOTES\n**************************\n"
				
				+ "\n\t * The function getToken sets the current user token, which will be used for any further operations"
				+ "\n\t * Get a new token by pressing the button with a different user name to change the current token"
				
		
				+ "\n\t * You will need to be logged into a Group Server to perform actions on the File Server"
				+ "\n\t * 1: Connect to a GroupServer"
				+ "\n\t * 2: Get a Token by following the steps above"
				+ "\n\n************************\nKEEP THIS OPEN TO READ SERVER RESPONSES\n**************************\n\n\n"
				);
		JScrollPane sp = new JScrollPane(console);
		log.add(sp);
		log.setSize(400,400);
		log.setVisible(true);
		return console;
	}
	
	class CustomOutputStream extends OutputStream {
	    private JTextArea textArea;
	     
	    public CustomOutputStream(JTextArea textArea) {
	        this.textArea = textArea;
	    }
	     
	    @Override
	    public void write(int b) throws IOException {
	        // redirects data to the text area
	        textArea.append(String.valueOf((char)b));
	        // scrolls the text area to the end of data
	        textArea.setCaretPosition(textArea.getDocument().getLength());
	    }
	}
	
	
	
	
	
	
	
	public static void main(String[] args) {  
	new ClientAppGUI(); 
	}
}
