package com.gs.email;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Properties;
import org.apache.log4j.PropertyConfigurator;

public class PropertyReader
{ 
	String appPath;
	public PropertyReader() throws Exception       
	{
		appPath = getAppPath();
	}

	public String getAppPath()
	{
		//return "C:/Users/GIHAN/Documents/eclipse workspace Seylan/SeylanProperties/config.properties";
		return "D:/IBM/SeylanBank/SeylanProperties/config.properties";
	}

	public Properties loadPropertyFile() throws Exception
	{
		try
		{
			Properties props = new Properties();
			FileInputStream fis = new FileInputStream(appPath);
			props.load(fis);
			fis.close();
			return props;
		}
		catch(Exception e)
		{
			e.fillInStackTrace();
			throw new Exception(e);
		}
	}

	public static String getProperty(Properties props, String propertyName)
			throws Exception
	{
		try
		{
			String propertyValue = (String)props.get(propertyName);
			if(propertyValue == null)
				throw new Exception((new StringBuilder("Property ")).append(propertyName).append(" is not define in loaded *.properties file").toString());
			else
				return propertyValue;
		}
		catch(Exception e)
		{
			throw e;
		}
	}

	public static void loadLogConfiguration(String logPropertyFile, String logFilePath)
	{
		Properties logProperties = new Properties();
		try
		{
			FileInputStream fis = new FileInputStream(logPropertyFile);
			logProperties.load(fis);
			fis.close();
		}
		catch(FileNotFoundException e)
		{
			System.out.println((new StringBuilder("Warning : ")).append(e).toString());
		}
		catch(IOException e)
		{
			System.out.println((new StringBuilder("Warning : ")).append(e).toString());
		}
		logProperties.setProperty("log4j.appender.A1.File", logFilePath);
		PropertyConfigurator.configure(logProperties);
	}

	public static void loadLogConfiguration(String logPropertyFile, String logFilePath, String logFileName)
	{
		Properties logProperties = new Properties();
		try
		{
			FileInputStream fis = new FileInputStream(logPropertyFile);
			logProperties.load(fis);
			fis.close();
		}
		catch(FileNotFoundException e)
		{
			System.out.println((new StringBuilder("Warning : ")).append(e).toString());
		}
		catch(IOException e)
		{
			System.out.println((new StringBuilder("Warning : ")).append(e).toString());
		}
		File file = new File(logFilePath);
		file.mkdirs();
		String logFile = (new StringBuilder(String.valueOf(logFilePath))).append("/").append(logFileName).toString();
		logProperties.setProperty("log4j.appender.A1.File", logFile);
		PropertyConfigurator.configure(logProperties);
	}

	public static void loadLogConfiguration(String logPropertyFile)
	{
		Properties logProperties = new Properties();
		try
		{
			FileInputStream fis = new FileInputStream(logPropertyFile);
			logProperties.load(fis);
			fis.close();
		}
		catch(FileNotFoundException e)
		{
			System.out.println((new StringBuilder("Warning : ")).append(e).toString());
		}
		catch(IOException e)
		{
			System.out.println((new StringBuilder("Warning : ")).append(e).toString());
		}
		PropertyConfigurator.configure(logProperties);
	}

	public static void main(String args[])
	{
		try
		{
			PropertyReader propReader = new PropertyReader();
			propReader.loadPropertyFile();
		}
		catch(Exception e)
		{
			e.printStackTrace();
		}
	}

}
