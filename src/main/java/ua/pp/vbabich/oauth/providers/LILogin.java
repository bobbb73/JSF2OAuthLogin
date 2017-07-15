package ua.pp.vbabich.oauth.providers;

import ua.pp.vbabich.oauth.OAuthProvider;
import ua.pp.vbabich.oauth.OAuthProviders;
import ua.pp.vbabich.oauth.util.HttpURL;
import ua.pp.vbabich.oauth.util.JsonHelper;
import ua.pp.vbabich.oauth.util.OAuthDAO;

import javax.annotation.PostConstruct;
import javax.enterprise.context.RequestScoped;
import javax.faces.context.FacesContext;
import javax.inject.Inject;
import javax.inject.Named;
import javax.json.Json;
import javax.json.JsonObject;
import java.io.StringReader;
import java.util.Properties;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

@Named("lilogin")
@RequestScoped
public class LILogin implements OAuthProvider {

	private final static Logger logger = Logger.getLogger(LILogin.class.getName());

	@Inject private OAuthProviders core;
	@Inject private OAuthDAO oauthDAO;

	private String apiKey;
	private String secretKey;
	private String redirectURI;
	private String code;
	private String recState;
	private String error;
	private String errorDescription;
	
	@PostConstruct
	public void init(){
		if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO,"init()");
		apiKey	=	oauthDAO.getProperty("linkedApiKey");
		secretKey=	oauthDAO.getProperty("linkedSecretKey");
		redirectURI=oauthDAO.getProperty("linkedRedirectURI");
	}

	@Override
	public String authorize(){
		if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO,"authorize() - start");
		try {
			core.setState(UUID.randomUUID().toString().replaceAll("-", ""));
			StringBuilder sb = new StringBuilder();
			sb.append("https://www.linkedin.com/uas/oauth2/authorization");
			sb.append("?response_type=code");
			sb.append("&client_id=").append(apiKey);
			sb.append("&scope=").append("r_basicprofile%20r_emailaddress"); 
			sb.append("&state=").append(core.getState());
			sb.append("&redirect_uri="); sb.append(redirectURI);
			FacesContext.getCurrentInstance().getExternalContext().redirect(sb.toString());
			if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO,"authorize() redirect="+sb.toString());
		} catch (Exception ex) {
			logger.log(Level.SEVERE, "authorize() error: ", ex);
		}
		return null;
	}

	@Override
	public void phase2(){
		if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO,"phase2() start");
		try {
			if (!core.getState().equals(recState)) {
				logger.log(Level.SEVERE,"phase2() error: state="+core.getState());
				logger.log(Level.SEVERE,"phase2() error: recState="+recState);
				throw new MyException("state not equals");
			}
			
			if (error!=null && !error.isEmpty()) {
				throw new MyException("User denied access: "+errorDescription);
			}
			
			if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO,"phase2() code="+code);

			StringBuilder sb = new StringBuilder();
			sb.append("https://www.linkedin.com/uas/oauth2/accessToken?grant_type=authorization_code");
			sb.append("&code=").append(code);
			sb.append("&redirect_uri=").append(redirectURI);
			sb.append("&client_id=").append(apiKey);
			sb.append("&client_secret=").append(secretKey);
			
			String ret = HttpURL.httpsPost(sb.toString(), new Properties(), "UTF-8");
			if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO,"phase2() ret="+ret);
			
			if (ret==null || ret.length()==0) throw new MyException("access_token is empty");

			Token token = decodeToken(ret);
			
			if (token==null) throw new MyException("Token==null");
			if (token.access_token==null) throw new MyException("access_token==null");
			if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO,"phase2() access_token="+token.access_token);
			
			String ret1 = HttpURL.httpsGet("https://api.linkedin.com/v1/people/~?oauth2_access_token="+token.access_token);
			if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO,"phase2() ret1="+ret1);

			if (ret1==null) throw new MyException("phase2 client info empty");
			
			String validatedId = parse(ret1);	// Достаем информацию из полученного профиля
			core.success(validatedId);
		} catch (Exception ex){
			logger.log(Level.SEVERE,"phase2() error: ",ex);
			core.errorRedirect(ex.getMessage());
		}
		if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO,"phase() 2 stop");
	}

    protected Token decodeToken(String json) {
        Token token = new Token();
		JsonObject jsonObject = Json.createReader(new StringReader(json)).readObject();
        token.access_token = JsonHelper.getStringValue(jsonObject, "access_token");
        token.expires_in = JsonHelper.getIntValue(jsonObject, "expires_in");
        return token;
    }

    class Token {
		public String access_token;
		public Integer expires_in;
	}

	private String parse(String str) {
		String fnameOpen = "<first-name>";
		String fnameClose = "</first-name>";
		String fname=str.substring(str.indexOf(fnameOpen)+fnameOpen.length(), str.indexOf(fnameClose));
		core.getUserAutoReqProps().setFirstName(fname);

		String lnameOpen = "<last-name>";
		String lnameClose = "</last-name>";
		String lname=str.substring(str.indexOf(lnameOpen)+lnameOpen.length(), str.indexOf(lnameClose));
		core.getUserAutoReqProps().setLastName(lname);

		String urlOpen = "<url>";
		String urlClose = "</url>";
		String url=str.substring(str.indexOf(urlOpen)+urlOpen.length(), str.indexOf(urlClose));
		return url.substring(0, url.indexOf("&amp;"));
	}
	
	class MyException extends Exception {
		private static final long serialVersionUID = 1L;

		public MyException(String message){
		     super(message);
		  }
	}
	
	public String getCode() {
		return code;
	}

	public void setCode(String code) {
		this.code = code;
	}

	public String getRecState() {
		return recState;
	}

	public void setRecState(String recState) {
		this.recState = recState;
	}

	public String getError() {
		return error;
	}

	public void setError(String error) {
		this.error = error;
	}

	public String getErrorDescription() {
		return errorDescription;
	}

	public void setErrorDescription(String errorDescription) {
		this.errorDescription = errorDescription;
	}
}
