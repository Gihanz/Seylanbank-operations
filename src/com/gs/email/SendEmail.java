package com.gs.email;

import java.io.File;
import java.io.FileOutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Properties;

import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.RijndaelEngine;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.encoders.Base64;

import javax.activation.DataHandler;
import javax.activation.DataSource;
import javax.activation.FileDataSource;
import javax.mail.Authenticator;
import javax.mail.BodyPart;
import javax.mail.Message;
import javax.mail.Multipart;
import javax.mail.PasswordAuthentication;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;

import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;

import com.google.gson.Gson;

public class SendEmail {
		
	static byte[] salt = new byte[]{1, 2, 3, 4, 5, 6, 7, 8};
	static int iterations = 1000;
	static int keySize = 256;
	static int blockSize = 128;
	
	private static Properties prop;
	private static String LOGO_PATH;
	private static String SMTP_HOST;
	private static String SMTP_PORT;
	private static String SMTP_AUTH_USER;
	private static String SMTP_AUTH_PWD;
	private static String SMTP_TIME_OUT;
	public static Logger log = Logger.getLogger(SendEmail.class);
	
	public SendEmail() {
		try{
			PropertyReader pr = new PropertyReader();
	    	prop = pr.loadPropertyFile();
	    	
			String pathSep = System.getProperty("file.separator");
	        String logpath = prop.getProperty("LOG4J_FILE_PATH");
	        String activityRoot = prop.getProperty("LOG_PATH");
			String logPropertyFile =logpath+pathSep+"log4j.properties"; 
	
			PropertyConfigurator.configure(logPropertyFile);
			PropertyReader.loadLogConfiguration(logPropertyFile, activityRoot+"/SendEmail/", "SendEmail.log");
			
			LOGO_PATH = prop.getProperty("LOGO_PATH");
			SMTP_HOST = prop.getProperty("SMTP_HOST");
			SMTP_PORT = prop.getProperty("SMTP_PORT");
			SMTP_AUTH_USER = prop.getProperty("SMTP_AUTH_USER");
			SMTP_AUTH_PWD = prop.getProperty("SMTP_AUTH_PWD");
			SMTP_TIME_OUT = prop.getProperty("SMTP_TIME_OUT");
		}catch(Exception e){
			System.out.println("Error : " +e.fillInStackTrace());
			log.info("Error : " +e.fillInStackTrace());
		}
	}
	
	public void send(String to, String from, String subject, String emailContent, String cc, String attachments, String decryptionKey) {
		
		try {
			boolean sessionDebug = false;

	        Properties props = System.getProperties();
	        props.put("mail.smtp.host", SMTP_HOST);
	        props.put("mail.smtp.port", SMTP_PORT);
	        props.put("mail.smtp.auth", "true");
	        props.put("mail.smtp.starttls.enable", "false");
	        props.put("mail.smtp.starttls.required", "false");
	        props.put("mail.smtp.timeout", SMTP_TIME_OUT);
	        
	        Authenticator auth = new Authenticator() {
				protected PasswordAuthentication getPasswordAuthentication() {
					String authPassword = decryptorSHA(SMTP_AUTH_PWD, decryptionKey);
					return new PasswordAuthentication(SMTP_AUTH_USER, authPassword);
				}
			};
	      
	        log.info("E-Mail sending to "+to+" ... (Subject:"+subject+")");
	      //java.security.Security.addProvider(new com.sun.net.ssl.internal.ssl.Provider());
	        Session mailSession = Session.getInstance(props, auth);
	        mailSession.setDebug(sessionDebug);
	        Message msg = new MimeMessage(mailSession);
	        msg.addHeader("Content-type", "text/HTML; charset=UTF-8");
		    msg.addHeader("format", "flowed");
		    msg.addHeader("Content-Transfer-Encoding", "8bit");
	        msg.setFrom(new InternetAddress(from));
	        
	      //multiple address in Adress TO		
			List<String> toRecipientsArray = Arrays.asList(to.split("\\s*,\\s*"));

			InternetAddress[] addressTo = new InternetAddress[toRecipientsArray.size()];
			for (int i=0; i<toRecipientsArray.size(); i++)
			{
				addressTo[i] = new InternetAddress(toRecipientsArray.get(i).toString()) ;
			}
			msg.setRecipients(Message.RecipientType.TO, addressTo);
			
		  //multiple address in Adress CC	
			if(cc != null){
				List<String> ccRecipientsArray = Arrays.asList(cc.split("\\s*,\\s*"));

				InternetAddress[] addressCC = new InternetAddress[ccRecipientsArray.size()];
				for (int i=0; i<ccRecipientsArray.size(); i++)
				{
					addressCC[i] = new InternetAddress(ccRecipientsArray.get(i).toString()) ;
				}
				msg.addRecipients(Message.RecipientType.CC, addressCC);
			}
			   
	        msg.setSubject(subject); 
	        msg.setSentDate(new Date());
	        
	     // creates multi-part
	        Multipart multipart = new MimeMultipart();
	        
	     // creates message part
	        BodyPart messageBodyPart = new MimeBodyPart();
	        messageBodyPart.setContent(emailContent, "text/html");
	        multipart.addBodyPart(messageBodyPart);
	        
	     // creates attachments part
	        if(attachments != null){
	        	Attachment[] attachmentsList = new Gson().fromJson(attachments, Attachment[].class);
	        	for(int x=0; x<attachmentsList.length; x++){
	            	
	            	byte[] data = Base64.decode(attachmentsList[x].getDataStream());
	            	final String PREFIX = "Seylan CASA";
	                final String SUFFIX = ".tmp";
	                  
	                File tempFile = File.createTempFile(PREFIX, SUFFIX);
	                tempFile.deleteOnExit();
	                try (FileOutputStream stream = new FileOutputStream(tempFile)) {
	                	stream.write(data);
	                }
	                
	                BodyPart attachmentBodyPart = new MimeBodyPart();
	                DataSource dSource = new FileDataSource(tempFile);               
	                attachmentBodyPart.setDataHandler(new DataHandler(dSource));
	                attachmentBodyPart.setFileName(attachmentsList[x].getAttachmentName()+".pdf");
	                attachmentBodyPart.setHeader("Content-ID", "attachment");
	                multipart.addBodyPart(attachmentBodyPart);       	
	            }	
	        }
	        
	     // setting customer logo
	        BodyPart logoImagePart = new MimeBodyPart();
	        DataSource img = new FileDataSource(LOGO_PATH);
	        logoImagePart.setDataHandler(new DataHandler(img));
	        logoImagePart.setHeader("Content-ID", "<logo>");
	        logoImagePart.setFileName("logo.png");
	        logoImagePart.setDisposition(MimeBodyPart.INLINE);
	        multipart.addBodyPart(logoImagePart);
	        
	        msg.setContent(multipart);
	        Transport.send(msg);
	        
	        System.out.println("E-Mail sent successfully");
	        log.info("E-Mail sent Successfully. To:"+to+", Cc:"+cc+", Subject:"+subject+", Content:"+emailContent);	
	        
		}catch (Exception e) {
			
			StringWriter sw = new StringWriter();
			PrintWriter pw = new PrintWriter(sw);
			e.printStackTrace(pw);
			
			e.printStackTrace();
			log.info("Exception occured : " +sw.toString());
		}	
	}
	
	private String encryptAES(String word, String password, byte[] salt, int iterations, int keySize, int blockSize) {
        try {
            byte[] pswd = sha256String(password, "UTF-8");
            PKCS5S2ParametersGenerator key = keyGeneration(pswd, salt, iterations);
            ParametersWithIV iv = generateIV(key, keySize, blockSize);
            BufferedBlockCipher cipher = getCipher(true, iv);
            byte[] inputText = word.getBytes("UTF-8");
            byte[] newData = new byte[cipher.getOutputSize(inputText.length)];
            int l = cipher.processBytes(inputText, 0, inputText.length, newData, 0);
            cipher.doFinal(newData, l);
            return new String(Base64.encode(newData), "UTF-8");
        } catch (UnsupportedEncodingException | IllegalStateException | DataLengthException | InvalidCipherTextException e) {
        	e.printStackTrace();
        	log.info("Error encryptAES : " +e.fillInStackTrace());
            return null;
        }
    }
    
	private String decryptAES(String word, String password, byte[] salt, int iterations, int keySize, int blockSize) {
        try {
            byte[] pswd = sha256String(password, "UTF-8");
            PKCS5S2ParametersGenerator key = keyGeneration(pswd, salt, iterations);
            ParametersWithIV iv = generateIV(key, keySize, blockSize);
            BufferedBlockCipher cipher = getCipher(false, iv);
            byte[] inputText = Base64.decode(word.getBytes());
            byte[] newData = new byte[cipher.getOutputSize(inputText.length)];
            int l = cipher.processBytes(inputText, 0, inputText.length, newData, 0);
            l += cipher.doFinal(newData, l);
            byte[] bytesDec = new byte[l];
            System.arraycopy(newData, 0, bytesDec, 0, l);            
            return new String(bytesDec);  
        } catch (IllegalStateException | DataLengthException | InvalidCipherTextException e) {
        	e.printStackTrace();
        	log.info("Error decryptAES : " +e.fillInStackTrace());
            return null;
        }
    }

	private BufferedBlockCipher getCipher(boolean encrypt, ParametersWithIV iv) {
        RijndaelEngine rijndael = new RijndaelEngine();
        BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(rijndael));
        cipher.init(encrypt, iv);
        return cipher;
    }
    
	private ParametersWithIV generateIV(PKCS5S2ParametersGenerator key, int keySize, int blockSize) {
        try {
            ParametersWithIV iv = null;
            iv = ((ParametersWithIV) key.generateDerivedParameters(keySize, blockSize));
            return iv;
        } catch (Exception e) {
        	e.printStackTrace();
        	log.info("Error generateIV : " +e.fillInStackTrace());
            return null;
        }
    }

	private PKCS5S2ParametersGenerator keyGeneration(byte[] password, byte[] salt, int iterations) {
        try {
            PKCS5S2ParametersGenerator key = new PKCS5S2ParametersGenerator();
            key.init(password, salt, iterations);
            return key;
        } catch (Exception e) {
        	e.printStackTrace();
        	log.info("Error keyGeneration : " +e.fillInStackTrace());
            return null;
        }
    }

	private byte[] sha256String(String password, Charset charset) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(password.getBytes(charset));
            return md.digest();
        } catch (NoSuchAlgorithmException ex) {
        	ex.printStackTrace();
        	log.info("Error sha256String : " +ex.fillInStackTrace());
            return null;
        }
    }

	private byte[] sha256String(String password, String charset) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(password.getBytes(charset));
            return md.digest();
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException ex) {
        	ex.printStackTrace();
        	log.info("Error sha256String : " +ex.fillInStackTrace());
            return null;
        }
    }
    
	private String encryptorSHA(String strInputText, String password) {
		
		if(strInputText == null){
            return null;
        }
		return encryptAES(strInputText, password, salt, iterations, keySize, blockSize);
	}
	
	private String decryptorSHA(String encryptedText, String password) {
		
		if(encryptedText == null){
            return null;
        }
		return decryptAES(encryptedText, password, salt, iterations, keySize, blockSize);
	}
}
