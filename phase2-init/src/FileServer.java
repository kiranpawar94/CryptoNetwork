/* FileServer loads files from FileList.bin.  Stores files in shared_files directory. */

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;



public class FileServer extends Server {
	
	public static final int SERVER_PORT = 4321;
	public static FileList fileList;
	
	 public Crypto.RSA RSAProvider;
	 public Crypto.SHA256 DigestProvider;
	public String pubKeyFileName;
	public String privKeyFileName;
	public FileServer() {
		super(SERVER_PORT, "FilePile");
	}

	public FileServer(int _port) {
		super(_port, "FilePile");
	}
	
	public void start() {
		String fileFile = "FileList.bin";
		ObjectInputStream fileStream;
		
		//This runs a thread that saves the lists on program exit
		Runtime runtime = Runtime.getRuntime();
		Thread catchExit = new Thread(new ShutDownListenerFS());
		runtime.addShutdownHook(catchExit);
		
		//Open user file to get user list
		try
		{
			FileInputStream fis = new FileInputStream(fileFile);
			fileStream = new ObjectInputStream(fis);
			fileList = (FileList)fileStream.readObject();
		}
		catch(FileNotFoundException e)
		{
			System.out.println("FileList Does Not Exist. Creating FileList...");
			
			fileList = new FileList();
			
		}
		catch(IOException e)
		{
			System.out.println("Error reading from FileList file");
			System.exit(-1);
		}
		catch(ClassNotFoundException e)
		{
			System.out.println("Error reading from FileList file");
			System.exit(-1);
			}
		
		File file = new File("shared_files");
		 if (file.mkdir()) {
			 System.out.println("Created new shared_files directory");
		 }
		 else if (file.exists()){
			 System.out.println("Found shared_files directory");
		 }
		 else {
			 System.out.println("Error creating shared_files directory");				 
		 }
		
		//Autosave Daemon. Saves lists every 5 minutes
		AutoSaveFS aSave = new AutoSaveFS();
		aSave.setDaemon(true);
		aSave.start();
		
		
		boolean running = true;
		if (this.setupRSA()) {
			try
			{			
				final ServerSocket serverSock = new ServerSocket(port);
				System.out.printf("%s up and running\n", this.getClass().getName());
			
				Socket sock = null;
				Thread thread = null;
			
				while(running)
				{
					sock = serverSock.accept();
					thread = new FileThread(sock, this);
					thread.start();
				}
			
				System.out.printf("%s shut down\n", this.getClass().getName());
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
		//Generate names so they don't match any user's (no "_") or the server, and there can be various servers running in a machine (different port)
		pubKeyFileName = "fs" + String.valueOf(port) + "pubkey";
		privKeyFileName = "fs" + String.valueOf(port) + "privkey";
		
		Crypto crypto = new Crypto();
		RSAProvider = crypto.new RSA(pubKeyFileName, privKeyFileName);
		DigestProvider = crypto.new SHA256();
		try {
			File fpub = new File(pubKeyFileName);
			File fpriv = new File(privKeyFileName);
			if (!(fpub.exists() && fpriv.exists())) {
				System.out.println("\nGenerating RSA keys and storing them in files named \""+ pubKeyFileName + "\" and \"" + privKeyFileName + "\" for the public and private keys, respectively");

				RSAProvider.generateRSAKeys();
			} else {
				System.out.println("\nRSA keypair found for file server running on port " + String.valueOf(port));
			}	
			return true;
		} catch(Exception e) {
			System.err.println("Error generating RSA keys for the Client: " + e.getMessage());
			e.printStackTrace(System.err);
		}
		return false;
	}
}

//This thread saves user and group lists
class ShutDownListenerFS implements Runnable
{
	public void run()
	{
		System.out.println("Shutting down server");
		ObjectOutputStream outStream;

		try
		{
			outStream = new ObjectOutputStream(new FileOutputStream("FileList.bin"));
			outStream.writeObject(FileServer.fileList);
		}
		catch(Exception e)
		{
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
	}
}

class AutoSaveFS extends Thread
{
	public void run()
	{
		do
		{
			try
			{
				Thread.sleep(300000); //Save group and user lists every 5 minutes
				System.out.println("Autosave file list...");
				ObjectOutputStream outStream;
				try
				{
					outStream = new ObjectOutputStream(new FileOutputStream("FileList.bin"));
					outStream.writeObject(FileServer.fileList);
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
