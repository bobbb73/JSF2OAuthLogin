package ua.pp.vbabich.oauth.providers;

import ua.pp.vbabich.oauth.OAuthProvider;
import ua.pp.vbabich.oauth.OAuthProviders;
import ua.pp.vbabich.oauth.util.HttpURL;
import ua.pp.vbabich.oauth.util.OAuthDAO;

import javax.annotation.PostConstruct;
import javax.enterprise.context.RequestScoped;
import javax.faces.context.ExternalContext;
import javax.faces.context.FacesContext;
import javax.inject.Inject;
import javax.inject.Named;
import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.servlet.http.HttpServletResponse;
import java.io.OutputStream;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.util.Properties;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

@Named(value="goologin")
@RequestScoped
public class GooLogin implements OAuthProvider {

	private static Logger logger = Logger.getLogger(GooLogin.class.getName());
	private String code;
	private String recState;
	private String gooId;
	private String gooRedirect;
	private String gooSecret; 

	@Inject private OAuthProviders core;
	@Inject private OAuthDAO oauthDAO;

	@PostConstruct
	public void init(){
		if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO,"init()");
		gooId = oauthDAO.getProperty("gooId");
		gooSecret = oauthDAO.getProperty("gooSecret");
		gooRedirect = oauthDAO.getProperty("gooRedirect");
	}

	@Override
	public String authorize(){
		if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO,"authorize() - start");
		core.setState(UUID.randomUUID().toString().replaceAll("-", ""));
		StringBuilder sb = new StringBuilder();
		sb.append("https://accounts.google.com/o/oauth2/auth?redirect_uri=");
		sb.append(gooRedirect);
		sb.append("&response_type=code&client_id=");
		sb.append(gooId);
		sb.append("&scope=https://www.googleapis.com/auth/userinfo.email%20https://www.googleapis.com/auth/userinfo.profile");
		sb.append("&state=");
		sb.append(core.getState());
		if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO,"authorize() request="+sb.toString());
		try {
            FacesContext.getCurrentInstance().getExternalContext().redirect(sb.toString());
		} catch (UnsupportedEncodingException e1) {
			logger.severe("login encoding redirect exception!" + e1.toString());
		} catch (Exception e) {
			logger.log(Level.SEVERE, "login redirect exception!", e);
		}
		if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO,"authorize() - end");
		return null;
	}

	@Override
	public void phase2(){
		try {
			if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO,"phase2() code="+code+" recState="+recState);
			
			// проверяем, что state переданный и полученный совпадают
			if (core.getState()==null || core.getState().length()==0) {
				logger.severe("phase2() error: sendState==null");
				throw new MyException("phase2() error: sendState==null");
			}
			
			if (!core.getState().endsWith(recState)) {
				FacesContext fc = FacesContext.getCurrentInstance();
			    ExternalContext ec = fc.getExternalContext();
			    HttpServletResponse response = (HttpServletResponse)ec.getResponse();
			    response.setStatus(401);
			    OutputStream output = ec.getResponseOutputStream();
			    output.write("Invalid state parameter.".getBytes());
				response.flushBuffer();
				logger.severe("phase2() sendState="+core.getState()+"recState="+recState);
				throw new MyException("phase2() error: !sendState.endsWith(recState)");
			}
			
			// все верно, продолжаем
			String ret1 = null;
			if (code != null && !code.isEmpty()){
				if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO,"phase2() send POST to https://accounts.google.com/o/oauth2/token");
				Properties props = new Properties();
				props.put("code", code);
				props.put("client_id", gooId);
				props.put("client_secret", gooSecret);
				props.put("grant_type", "authorization_code");
				props.put("redirect_uri", gooRedirect);
			    ret1 = HttpURL.httpsPost("https://accounts.google.com/o/oauth2/token", props, "UTF-8");
				if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO,"phase2() ret1=" + ret1);
			}
		
			// Ответ получен
			TokensPayload tokensPayload = decodePayload(ret1);
			if (logger.isLoggable(Level.INFO)) {
				logger.log(Level.INFO,"phase2() tokensPayload.access_token="+tokensPayload.access_token);
				logger.log(Level.INFO,"phase2() tokensPayload.token_type="+tokensPayload.token_type);
				logger.log(Level.INFO,"phase2() tokensPayload.expires_in="+tokensPayload.expires_in);
				logger.log(Level.INFO,"phase2() tokensPayload.id_token="+tokensPayload.id_token);
			}

			//	Раскрываем полученные данные 
			String[] arr = tokensPayload.id_token.split("\\.");
	
			if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO,"phase2() arr.length="+arr.length);
	
			String header = new String(javax.xml.bind.DatatypeConverter.parseBase64Binary(pad(arr[0])));
			String claimsJSON = new String(javax.xml.bind.DatatypeConverter.parseBase64Binary(pad(arr[1])));
	
			if (logger.isLoggable(Level.INFO)) {
				logger.log(Level.INFO, "phase2() header=" + header);
				logger.log(Level.INFO,"phase2() claimsJSON="+claimsJSON);
			}

			Claims claims = decodeClaims(claimsJSON);

			String personRet = HttpURL.httpsGet("https://www.googleapis.com/oauth2/v1/userinfo?alt=json&access_token="+tokensPayload.access_token);
			if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO,"personRet="+personRet);

			PersonData personData = decodePersonData(personRet);
			core.getUserAutoReqProps().setEmail(claims.email);
			core.getUserAutoReqProps().setFirstName(personData.given_name);
			core.getUserAutoReqProps().setLastName(personData.family_name);
			core.getUserAutoReqProps().setSex("male".equalsIgnoreCase(personData.gender));
            if (personData.link!=null)
                core.success(personData.link);
            else
                core.success("http://apps.googleusercontent.com/" + personData.id);
		} catch (Exception ex) {
			logger.log(Level.SEVERE, "phase2() error: ", ex);
            core.errorRedirect(ex.getMessage());
		}
	}

    protected TokensPayload decodePayload(String json) {
        TokensPayload tp = new TokensPayload();
		JsonReader jsonReader = Json.createReader(new StringReader(json));
		JsonObject jsonObject = jsonReader.readObject();
		tp.access_token = jsonObject.getString("access_token");
		tp.token_type = jsonObject.getString("token_type");
		tp.expires_in = jsonObject.getInt("expires_in");
		tp.id_token = jsonObject.getString("id_token");
		return tp;
    }

    protected Claims decodeClaims(String json) {
        Claims claims = new Claims();
		JsonReader jsonReader = Json.createReader(new StringReader(json));
		JsonObject jsonObject = jsonReader.readObject();
		claims.iss = jsonObject.getString("iss");
		claims.email_verified = jsonObject.getBoolean("email_verified");
		claims.sub = jsonObject.getString("sub");
		claims.aud = jsonObject.getString("aud");
		claims.at_hash = jsonObject.getString("at_hash");
		claims.email = jsonObject.getString("email");
		claims.azp = jsonObject.getString("azp");
		claims.iat = jsonObject.getInt("iat");
		claims.exp = jsonObject.getInt("exp");
		return claims;
    }

    protected PersonData decodePersonData(String json) {
        PersonData personData = new PersonData();
		JsonReader jsonReader = Json.createReader(new StringReader(json));
		JsonObject jsonObject = jsonReader.readObject();
		personData.id = jsonObject.getString("id");
		personData.email = jsonObject.getString("email");
		personData.name = jsonObject.getString("name");
		personData.verified_email = jsonObject.getBoolean("verified_email");
		personData.given_name = jsonObject.getString("given_name");
		personData.email = jsonObject.getString("email");
		personData.family_name = jsonObject.getString("family_name");
		personData.link = jsonObject.getString("link");
		personData.picture = jsonObject.getString("picture");
		personData.gender = jsonObject.getString("gender");
		personData.locale = jsonObject.getString("locale");
		return personData;
    }

    class TokensPayload {
		public String access_token;
		public String token_type;
		public Integer expires_in;
		public String id_token;
	}

	class Claims {
		public String iss;
		public Boolean email_verified;
		public String sub;
		public String aud;
		public String at_hash;
		public String email;
		public String azp;
		public Integer iat;
		public Integer exp;
	}

	class PersonData {
		public String id;
		public String email;
		public String name;
		public Boolean verified_email;
		public String given_name;
		public String family_name;
		public String link;
		public String picture;
		public String gender;
		public String locale;
	}

	public String pad(String str){
		switch (str.length() % 4) {
			default: return str;
			case 1: return str.concat("===");
			case 2: return str.concat("==");
			case 3: return str.concat("=");
		}
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

}
