package ua.pp.vbabich.oauth.providers;

import ua.pp.vbabich.oauth.OAuthProvider;
import ua.pp.vbabich.oauth.OAuthProviders;
import ua.pp.vbabich.oauth.util.HttpURL;
import ua.pp.vbabich.oauth.util.OAuthDAO;

import javax.annotation.PostConstruct;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.enterprise.context.RequestScoped;
import javax.faces.context.FacesContext;
import javax.inject.Inject;
import javax.inject.Named;
import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Properties;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

@Named(value="twlogin")
@RequestScoped
public class TWLogin implements OAuthProvider {

	private static Logger logger = Logger.getLogger(TWLogin.class.getName());

	@Inject private OAuthProviders core;
	@Inject private OAuthDAO oauthDAO;

	private String oauthConsumerKey;
	private String oauthSignatureMethod = "HMAC-SHA1";
	private String oauthToken;
	private String oauthVerifier;
	private String oauthVersion = "1.0";
	
	private String consumerSecret;

	private String requestTokenURL;
	private String accessTokenURL;
	private String callbackURL;

	@PostConstruct
	public void init(){
		if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO,"init()");
		oauthConsumerKey = oauthDAO.getProperty("twConsumerKey");
		consumerSecret = oauthDAO.getProperty("twConsumerSecret")+"&";
		requestTokenURL = oauthDAO.getProperty("twRequestTokenURL");
		accessTokenURL = oauthDAO.getProperty("twAccessTokenURL");
		callbackURL = oauthDAO.getProperty("twCallbackURL");
	}

	protected String computeSignature(String baseString, String keyString) throws NoSuchAlgorithmException, InvalidKeyException {
		SecretKey secretKey = null;
		byte[] keyBytes = keyString.getBytes();
		secretKey = new SecretKeySpec(keyBytes, "HmacSHA1");
		Mac mac = Mac.getInstance("HmacSHA1");
		mac.init(secretKey);
		byte[] text = baseString.getBytes();
		return DatatypeConverter.printBase64Binary(mac.doFinal(text));
	}

	@Override
	public String authorize() {
		if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO,"authorize() - start");
		try {

			// Получаем request token
			String timestamp = Long.toString(System.currentTimeMillis() / 1000);
			String nonce = UUID.randomUUID().toString().replaceAll("-", "");
			if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO,"authorize() nonce="+nonce);
			
			StringBuilder sb = new StringBuilder();
			sb.append("oauth_callback=");
			sb.append(percentEncode(callbackURL));
			sb.append("&oauth_consumer_key=");
			sb.append(oauthConsumerKey);
			sb.append("&oauth_nonce=");			sb.append(nonce);
			sb.append("&oauth_signature_method=");	sb.append(oauthSignatureMethod);
			sb.append("&oauth_timestamp=");		sb.append(timestamp);
			sb.append("&oauth_version=");
			sb.append(oauthVersion);
			
			String signature = percentEncode(computeSignature("POST&" + percentEncode(requestTokenURL) + "&" + percentEncode(sb.toString()), consumerSecret));
			if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO,"authorize() signature="+signature);

			sb = new StringBuilder();
			sb.append("OAuth ");
			sb.append("oauth_callback=");
			sb.append('"');
			sb.append(percentEncode(callbackURL));
			sb.append('"');
			sb.append(',');
			sb.append("oauth_consumer_key=");	sb.append('"');		sb.append(oauthConsumerKey);	sb.append('"');		sb.append(',');
			sb.append("oauth_nonce=");
			sb.append('"');
			sb.append(nonce);
			sb.append('"');
			sb.append(',');
			sb.append("oauth_signature=");
			sb.append('"');
			sb.append(signature);
			sb.append('"');
			sb.append(',');
			sb.append("oauth_signature_method=");
			sb.append('"');
			sb.append(oauthSignatureMethod);
			sb.append('"');
			sb.append(',');
			sb.append("oauth_timestamp=");		sb.append('"');		sb.append(timestamp);			sb.append('"');		sb.append(',');
			sb.append("oauth_version=");
			sb.append('"');
			sb.append(oauthVersion);
			sb.append('"');

			if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO,"authorize() Authorization="+sb.toString());
			
			Properties reqProps = new Properties();
			reqProps.put("Authorization", sb.toString());
			String ret = HttpURL.httpsPost(requestTokenURL, new Properties(), reqProps, "UTF-8");
			if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO, "authorize() ret=" + ret);
			if (ret == null) return null;
			oauthToken = ret.substring(ret.indexOf("oauth_token=") + 12, ret.indexOf("&oauth_token_secret="));
			if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO,"authorize() oauthToken="+oauthToken);

			// Отправляем пользователя на авторизацию
			FacesContext.getCurrentInstance().getExternalContext().redirect("https://api.twitter.com/oauth/authenticate?oauth_token=" + oauthToken);
			return null;
		} catch (Exception ex) {
			logger.log(Level.SEVERE, "authorize() error: ", ex);
		}

		try {
			FacesContext.getCurrentInstance().getExternalContext().redirect("/");
		} catch (IOException ex) {
			logger.log(Level.SEVERE, "phase2() redirect error: ", ex);
		}
		FacesContext.getCurrentInstance().getExternalContext().invalidateSession();
		return null;
	}

	@Override
	public void phase2(){
		if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO,"phase2() oauthToken="+oauthToken+" oauthVerifier="+oauthVerifier);
		try {

			// Получаем access token
			String timestamp = Long.toString(System.currentTimeMillis() / 1000);
			String nonce = UUID.randomUUID().toString().replaceAll("-", "");
			if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO,"phase2() nonce="+nonce);
	
			StringBuilder sb = new StringBuilder();
			sb.append("oauth_consumer_key=");	sb.append(oauthConsumerKey);
			sb.append("&oauth_nonce=");			sb.append(nonce);
			sb.append("&oauth_signature_method=");	sb.append(oauthSignatureMethod);
			sb.append("&oauth_timestamp=");		sb.append(timestamp);
			sb.append("&oauth_token=");			sb.append(oauthToken);
			sb.append("&oauth_version=");		sb.append(oauthVersion);
			
			String signature = percentEncode(computeSignature("POST&" + percentEncode(accessTokenURL) + "&" + percentEncode(sb.toString()), consumerSecret));
			if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO,"phase2() signature="+signature);
			
			sb = new StringBuilder();
			sb.append("OAuth ");
			sb.append("oauth_consumer_key=");	sb.append('"');		sb.append(oauthConsumerKey);	sb.append('"');		sb.append(",");
			sb.append("oauth_nonce=");			sb.append('"');		sb.append(nonce);				sb.append('"');		sb.append(",");
			sb.append("oauth_signature=");		sb.append('"');		sb.append(signature);			sb.append('"');		sb.append(",");
			sb.append("oauth_signature_method=");	sb.append('"');	sb.append(oauthSignatureMethod);sb.append('"');		sb.append(",");
			sb.append("oauth_timestamp=");		sb.append('"');		sb.append(timestamp);			sb.append('"');		sb.append(",");
			sb.append("oauth_token=");			sb.append('"');		sb.append(oauthToken);			sb.append('"');		sb.append(",");
			sb.append("oauth_version=");		sb.append('"');		sb.append(oauthVersion);		sb.append('"');
			
			if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO,"authorize() Authorization="+sb.toString());
			
			Properties reqProps = new Properties();
			reqProps.put("Authorization", sb.toString());
			
			Properties props = new Properties();
			props.put("oauth_verifier", oauthVerifier);
			
			String ret = HttpURL.httpsPost(accessTokenURL, props, reqProps, "UTF-8");
			if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO,"phase2() ret="+ret);
			
			Properties personData = parse(ret);
			if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO,"phase2() screen_name="+personData.getProperty("screen_name")+" user_id="+personData.getProperty("user_id"));
			core.success("http://twitter.com/" + personData.getProperty("screen_name"));

		} catch (Exception ex){
			logger.log(Level.SEVERE, "phase2() error: ", ex);
			core.errorRedirect(ex.getMessage());
		}
	}

	public Properties parse(String str){
		Properties props = new Properties();
		String[] arr1 = str.split("&");
		for (String anArr1 : arr1) {
			String[] arr2 = anArr1.split("=");
			props.put(arr2[0], arr2[1]);
		}
		return props;
	}

	public static final String ENCODING = "UTF-8";
    public static String percentEncode(String s) {
        if (s == null) {
            return "";
        }
        try {
            return URLEncoder.encode(s, ENCODING)
                    .replace("+", "%20").replace("*", "%2A")
                    .replace("%7E", "~");
        } catch (UnsupportedEncodingException ex) {
            logger.log(Level.SEVERE,"percentEncode() error: ", ex);
        }
        return null;
    }
    
	public String getOauthConsumerKey() {
		return oauthConsumerKey;
	}

	public void setOauthConsumerKey(String oauthConsumerKey) {
		this.oauthConsumerKey = oauthConsumerKey;
	}

	public String getOauthSignatureMethod() {
		return oauthSignatureMethod;
	}

	public String getOauthToken() {
		return oauthToken;
	}

	public void setOauthToken(String oauthToken) {
		this.oauthToken = oauthToken;
	}

	public String getOauthVersion() {
		return oauthVersion;
	}

	public String getOauthVerifier() {
		return oauthVerifier;
	}

	public void setOauthVerifier(String oauthVerifier) {
		this.oauthVerifier = oauthVerifier;
	}
}
