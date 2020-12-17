import java.io.*;
import java.util.*;


public class EnvelopeEncryptionUtil {
    public static Envelope encryptEnvelope(Envelope env, Crypto.AES AESProvider) throws IOException {
        Envelope s = new Envelope("ENCRYPTED_DATA");
        byte[] envInBytes = envToByte(env);
        byte[] cipher = AESProvider.AESEncryptBytes(envInBytes);
        System.out.println("cipher length: " + cipher.length);
        s.addObject(cipher);
        return s;
    } 
    public static Envelope decryptEnvelope(Envelope s, Crypto.AES AESProvider) throws IOException, ClassNotFoundException {
        if (s.getMessage().equals("ENCRYPTED_DATA") && s.getObjContents().size() == 1) {
            byte[] cipher = (byte[])s.getObjContents().get(0);
            System.out.println("cipher length: " + cipher.length);
            byte[] envInBytes = AESProvider.AESDecryptBytes(cipher);
            Envelope env = (Envelope)byteToObj(envInBytes);
            return env;
        }
        return null;
    }

    private static byte[] envToByte(Envelope env) throws IOException {
    	ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
    	ObjectOutputStream objStream = new ObjectOutputStream(byteStream);
    	objStream.writeObject(env);

    	return byteStream.toByteArray();
	}

	private static Object byteToObj(byte[] bytes) throws IOException, ClassNotFoundException {
    	ByteArrayInputStream byteStream = new ByteArrayInputStream(bytes);
    	ObjectInputStream objStream = new ObjectInputStream(byteStream);
    	return objStream.readObject();
    }
}