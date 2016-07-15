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
import java.security.MessageDigest;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

@Named(value="odlogin")
@RequestScoped
public class ODLogin implements OAuthProvider {

	private String odId;
	private String odPublic;
	private String odSecret;
	private static Logger logger = Logger.getLogger(ODLogin.class.getName());
	private String parmRedirectURL;
	private String code;
	private String error;

	@Inject private OAuthProviders core;
	@Inject private OAuthDAO oauthDAO;

	@PostConstruct
	public void init(){
		odId = oauthDAO.getProperty("odId");
		odPublic = oauthDAO.getProperty("odPublic");
		odSecret = oauthDAO.getProperty("odSecret");
		parmRedirectURL = core.getContextURL().concat("/pages/login/odLogin.jsf");
	}

	@Override
	public String authorize(){
		if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO,"OD authorize() - start");
		error=null;
		String plainUrl = "http://www.odnoklassniki.ru/oauth/authorize?"
				+"client_id=" + odId
				+"&response_type=code"
				+"&redirect_uri=" + parmRedirectURL;

		try {
            FacesContext.getCurrentInstance().getExternalContext().redirect(plainUrl);
		} catch (UnsupportedEncodingException e1) {
			logger.severe("login encoding redirect exception!" + e1.toString());
		} catch (Exception e) {
			logger.severe("login redirect exception!" + e.toString());
		}
		if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO,"OD authorize() - end");
		return "";
	}

	@Override
	public void phase2(){
		if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO,"OD Phase 2 - start");

		if (error!=null) {
            core.errorRedirect(error);
			return;
		}

		if (code != null && !code.isEmpty()){
			if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO,"code="+code);
			Properties props = new Properties();
			props.put("code", code);
			props.put("redirect_uri",parmRedirectURL);
			props.put("grant_type","authorization_code");
			props.put("client_id",odId);
			props.put("client_secret",odSecret);
		    String ret1 = HttpURL.httpsPost("https://api.odnoklassniki.ru/oauth/token.do", props, "UTF-8");

			if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO,"ret1=" + ret1);
			OD od = decodeAccess(ret1);
			if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO,"access_token=" + od.access_token);

			/////////////////////////////////////////////////////////////////////////////
			String parm1 = od.access_token + odSecret;

			byte[] bytesOfMessage1 = null;
			MessageDigest md = null;
			String hashtext1 = null;
			try {
				md = MessageDigest.getInstance("MD5");
				bytesOfMessage1 = parm1.getBytes("UTF-8");
				byte[] md5digest1 = md.digest(bytesOfMessage1);
				hashtext1 = byteArrayToHex(md5digest1);
			} catch (Exception e) {
				e.printStackTrace();
			}

			String parm2 = "application_key="+odPublic+"method=users.getCurrentUser"+hashtext1;
            String sig = null;
			byte[] bytesOfMessage2;
			try {
				bytesOfMessage2 = parm2.getBytes("UTF-8");
                byte[] md5digest2 = md.digest(bytesOfMessage2);
                sig = byteArrayToHex(md5digest2);
            } catch (Exception e) {
				logger.log(Level.WARNING, "Error:", e);
			}

			/////////////////////////////////////////////////////////////////////////////
			String ret2 = HttpURL.httpGet("http://api.odnoklassniki.ru/fb.do?method=users.getCurrentUser&access_token="+od.access_token+"&application_key="+odPublic+"&sig="+sig);

			if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO,"ret2="+ret2);

			PersonData personData = decodePersonData(ret2);

			if (logger.isLoggable(Level.INFO)) {
                logger.log(Level.INFO,"uid=" + personData.uid);
                logger.log(Level.INFO,"birthday=" + personData.birthday);
                logger.log(Level.INFO,"age=" + personData.age);
                logger.log(Level.INFO,"first_name=" + personData.first_name);
                logger.log(Level.INFO,"last_name=" + personData.last_name);
                logger.log(Level.INFO,"gender=" + personData.gender);
            }

			core.getUserAutoReqProps().setLastName(personData.last_name);
			core.getUserAutoReqProps().setFirstName(personData.first_name);
			core.getUserAutoReqProps().setSex(!"male".equalsIgnoreCase(personData.gender));
			try {
                final SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd");
				core.getUserAutoReqProps().setBorn(formatter.parse(personData.birthday));
			} catch (ParseException e) {
				logger.log(Level.WARNING, "Error:", e);
			}

			String link = "http://www.odnoklassniki.ru/profile/" + personData.uid;
			core.success(link);
		}
		if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO,"OD Phase 2 - end");
	}

    protected OD decodeAccess(String json) {
        OD od = new OD();
        JsonReader jsonReader = Json.createReader(new StringReader(json));
        JsonObject jsonObject = jsonReader.readObject();
        od.access_token = jsonObject.getString("access_token");
        od.refresh_token = jsonObject.getString("refresh_token");
        od.token_type = jsonObject.getString("token_type");
        return od;
    }

    protected PersonData decodePersonData(String json) {
        PersonData personData= new PersonData();
        JsonReader jsonReader = Json.createReader(new StringReader(json));
        JsonObject jsonObject = jsonReader.readObject();
        personData.last_name = jsonObject.getString("last_name");
        personData.first_name = jsonObject.getString("first_name");
        personData.gender = jsonObject.getString("gender");
        personData.birthday = jsonObject.getString("birthday");
        personData.uid = jsonObject.getString("uid");
        personData.age = jsonObject.getInt("age");;
        return personData;
    }

    class OD {
		String token_type;
		String refresh_token;
		String access_token;
	}

	class PersonData {
		public String uid;
		public String birthday;
		public Integer  age;
		public String first_name;
		public String last_name;
		public String gender;
    	public String locale;
	}

	protected String byteArrayToHex(byte[] a) {
        return javax.xml.bind.DatatypeConverter.printHexBinary(a).toLowerCase();
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
