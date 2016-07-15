package ua.pp.vbabich.oauth.util;

import javax.net.ssl.HttpsURLConnection;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

public class HttpURL {
	private static final Logger logger = Logger.getLogger(HttpURL.class.getName());

	public static String httpsGet(String strurl){
		try {
			StringBuilder ret = new StringBuilder();
			URL url = new URL(strurl);
			HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
		    BufferedReader rd = new BufferedReader(new InputStreamReader(conn.getInputStream()));
		    String line;
		    while ((line = rd.readLine()) != null) ret.append(line);
		    rd.close();
		    return ret.toString();
		} catch (Exception e) {
			logger.log(Level.SEVERE,"httpsGet url.openConnection() error:", e);
			return null;
		}
	}
	
	public static String httpGet(String strurl){
		try {
			StringBuilder ret = new StringBuilder();
			URL url = new URL(strurl);
			HttpURLConnection conn = (HttpURLConnection) url.openConnection();
		    BufferedReader rd = new BufferedReader(new InputStreamReader(conn.getInputStream()));
		    String line;
		    while ((line = rd.readLine()) != null) ret.append(line);
		    rd.close();
		    return ret.toString();
		} catch (Exception e) {
			logger.log(Level.SEVERE,"httpGet url.openConnection() error:", e);
			return null;
		}
	}
	
	public static String httpsPost(String strurl, Properties parms, String encoding){
		try {
			StringBuilder ret = new StringBuilder();
			StringBuilder data = new StringBuilder();
			int i=0;
			for (Entry<Object, Object> prop: parms.entrySet()){
				if (i++ > 0) data.append('&');
				data.append(URLEncoder.encode((String) prop.getKey(), encoding)).append('=').append(URLEncoder.encode((String) prop.getValue(), encoding));
			}        
			URL url = new URL(strurl);
			HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
			conn.setDoOutput(true);
	        OutputStreamWriter wr = new OutputStreamWriter(conn.getOutputStream());
	        wr.write(data.toString());
	        wr.flush();
			
		    BufferedReader rd = new BufferedReader(new InputStreamReader(conn.getInputStream()));
		    String line;
		    while ((line = rd.readLine()) != null) ret.append(line);
		    rd.close();
		    return ret.toString();
		} catch (Exception e) {
			logger.log(Level.SEVERE, "httpsPost url.openConnection() error:", e);
			return null;
		}
	}

	public static String httpsPost(String strurl, Properties parms, Properties reqestParms, String encoding){
		try {
			StringBuilder ret = new StringBuilder();
			StringBuilder data = new StringBuilder();
			int i=0;
			for (Entry<Object, Object> prop: parms.entrySet()){
				if (i++ > 0) data.append('&');
				data.append(URLEncoder.encode((String) prop.getKey(), encoding)).append('=').append(URLEncoder.encode((String) prop.getValue(), encoding));
			}
			URL url = new URL(strurl);
			HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
			conn.setDoOutput(true);
			for (Entry<Object, Object> prop: reqestParms.entrySet()){
				conn.setRequestProperty(prop.getKey().toString(), prop.getValue().toString());				
			}
	        OutputStreamWriter wr = new OutputStreamWriter(conn.getOutputStream());
	        wr.write(data.toString());
	        wr.flush();
			
		    BufferedReader rd = new BufferedReader(new InputStreamReader(conn.getInputStream()));
		    String line;
		    while ((line = rd.readLine()) != null) ret.append(line);
		    rd.close();
		    return ret.toString();
		} catch (Exception e) {
			logger.log(Level.SEVERE, "httpsPost url.openConnection() error:", e);
			return null;
		}
	}

}
