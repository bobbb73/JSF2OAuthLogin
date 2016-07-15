package ua.pp.vbabich.oauth.providers;

import ua.pp.vbabich.oauth.OAuthProvider;
import ua.pp.vbabich.oauth.OAuthProviders;
import ua.pp.vbabich.oauth.util.HttpURL;
import ua.pp.vbabich.oauth.util.OAuthDAO;

import javax.annotation.PostConstruct;
import javax.enterprise.context.RequestScoped;
import javax.faces.context.FacesContext;
import javax.inject.Inject;
import javax.inject.Named;
import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

@Named(value="mrlogin")
@RequestScoped
public class MRLogin implements OAuthProvider {

	private static Logger logger = Logger.getLogger(MRLogin.class.getName());
	private String mailRuId;
	private String mailRuPrivateKey;
	private String mailRuSecretKey;
	private String parmRedirectURL;

	private String code;
	private String error;

	@Inject private OAuthProviders core;
	@Inject private OAuthDAO oauthDAO;

	@PostConstruct
	public void init(){
		mailRuId = oauthDAO.getProperty("mailRuId");
		mailRuPrivateKey = oauthDAO.getProperty("mailRuPrivateKey");
		mailRuSecretKey = oauthDAO.getProperty("mailRuSecretKey");
		parmRedirectURL = core.getContextURL().concat("/pages/login/mrLogin.jsf");
	}

	@Override
	public String authorize(){
		if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO,"MR authorize() - start");
		error=null;
		String plainUrl = "https://connect.mail.ru/oauth/authorize?" 
				+ "client_id="+ mailRuId
				+"&response_type=code"
				+"&redirect_uri=" + parmRedirectURL;
		try {
            FacesContext.getCurrentInstance().getExternalContext().redirect(plainUrl);
		} catch (UnsupportedEncodingException e1) {
			logger.severe("MR login encoding redirect exception!" + e1.toString());
		} catch (Exception e) {
			logger.severe("MR login redirect exception!" + e.toString());
		}
		if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO,"MR authorize() - end");
		return "";
	}

	@Override
	public void phase2(){
		if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO,"Phase 2 - start: code="+code+" error="+error);

		if (error!=null) {
            core.errorRedirect(error);
			return;
		}

		if (code != null && !code.isEmpty()){
			Properties props = new Properties();
			props.put("client_id", mailRuId);
			props.put("client_secret", mailRuPrivateKey);
			props.put("grant_type", "authorization_code");
			props.put("code", code);
			props.put("redirect_uri", parmRedirectURL);
			if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO,"phase2(): client_id="+mailRuId+" client_secret="+mailRuPrivateKey+" code="+code+" redirect_uri="+parmRedirectURL );
		    String ret1 = HttpURL.httpsPost("https://connect.mail.ru/oauth/token", props, "UTF-8");

			if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO,"ret1=" + ret1);

			MR mr = decodeToken(ret1);
			if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO,"access_token=" + mr.access_token);
			if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO,"x_mailru_vid=" + mr.x_mailru_vid);

			String parm = "app_id=" + mailRuId
					+"method=users.getInfo"
					+"secure=1"
					+"session_key=" + mr.access_token
					+"uids=" + mr.x_mailru_vid
					+ mailRuSecretKey;

			byte[] bytesOfMessage = null;
			MessageDigest md = null;
			try {
				md = MessageDigest.getInstance("MD5");
				bytesOfMessage = parm.getBytes("UTF-8");
			} catch (Exception e) {
				logger.log(Level.WARNING, "Error:", e);
			}

			byte[] md5digest = md.digest(bytesOfMessage);
			BigInteger bigInt = new BigInteger(1,md5digest);
			String hashtext = bigInt.toString(16);

			String apiURL = "http://www.appsmail.ru/platform/api?"
					+"method=users.getInfo"
					+"&app_id=" + mailRuId
					+"&session_key=" + mr.access_token
					+"&sig=" + hashtext
					+"&uids=" + mr.x_mailru_vid
					+"&secure=1";

			if (logger.isLoggable(Level.INFO)) {
                logger.log(Level.INFO,"hashtext=" + hashtext);
                logger.log(Level.INFO,"apiURL=" + apiURL);
            }

		    String ret2 = HttpURL.httpGet(apiURL);

			if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO,"ret2="+ret2);

			PersonData personData = decodePersonData(ret2);
			if (logger.isLoggable(Level.INFO)) {
                logger.log(Level.INFO,"nick=" + personData.nick);
                logger.log(Level.INFO,"first_name="+personData.first_name);
                logger.log(Level.INFO,"last_name="+personData.last_name);
                logger.log(Level.INFO,"birthday="+personData.birthday);
                logger.log(Level.INFO,"link="+personData.link);
                logger.log(Level.INFO,"uid="+personData.uid);
                logger.log(Level.INFO,"sex="+personData.sex);
                logger.log(Level.INFO,"email="+personData.email);
            }

			core.getUserAutoReqProps().setEmail(personData.email);
			core.getUserAutoReqProps().setLastName(personData.last_name);
			core.getUserAutoReqProps().setFirstName(personData.first_name);
			core.getUserAutoReqProps().setSex(personData.sex==0);

			try {
				DateFormat dateFormat = new SimpleDateFormat("dd.MM.yyyy");
				core.getUserAutoReqProps().setBorn(dateFormat.parse(personData.birthday));
			} catch(Exception ex) {
				logger.log(Level.WARNING, "Error:", ex);
			};
            core.success(personData.link);
		}
		if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO,"Phase 2 - end");
	}

	protected MR decodeToken(String json) {
        MR mr = new MR();
        JsonReader jsonReader = Json.createReader(new StringReader(json));
        JsonObject jsonObject = jsonReader.readObject();
        mr.access_token = jsonObject.getString("access_token");
        mr.refresh_token = jsonObject.getString("refresh_token");
        mr.expires_in = jsonObject.getInt("expires_in");
        mr.token_type = jsonObject.getString("token_type");
        mr.x_mailru_vid = jsonObject.getString("x_mailru_vid");
        return mr;
	}

	protected PersonData decodePersonData(String json) {
        PersonData personData = new PersonData();
        JsonReader jsonReader = Json.createReader(new StringReader(json.substring(1)));
        JsonObject jsonObject = jsonReader.readObject();
        personData.nick = jsonObject.getString("nick");
        personData.first_name = jsonObject.getString("first_name");
        personData.last_name = jsonObject.getString("last_name");
        personData.birthday = jsonObject.getString("birthday");
        personData.link = jsonObject.getString("link");
        personData.uid = jsonObject.getString("uid");
        personData.sex = jsonObject.getInt("sex");
        personData.email = jsonObject.getString("email");
        return personData;
	}

	class MR {
		String access_token;
		String refresh_token;
		Integer expires_in;
		String token_type;
		String x_mailru_vid;
	}

	class PersonData {
        public String nick;
        public String first_name;
        public String last_name;
        public String birthday;
        public String link;
        public String uid;
        public Integer sex;
        public String email;
    }

    public String getCode() {
		return code;
	}

	public void setCode(String code) {
		this.code = code;
	}

	public String getError() {
		return error;
	}

	public void setError(String error) {
		this.error = error;
	}
}
