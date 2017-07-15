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
import java.io.UnsupportedEncodingException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

@Named(value="yalogin")
@RequestScoped
public class YALogin implements OAuthProvider {

	private String yaId;
	private String yaSecret;

	private static Logger logger = Logger.getLogger(YALogin.class.getName());
	private String code;
	private String error;
	private String state;

	@Inject private OAuthProviders core;
	@Inject private OAuthDAO oauthDAO;

	@PostConstruct
	public void init(){
		if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO,"init()");
		yaId = oauthDAO.getProperty("yaId");
		yaSecret = oauthDAO.getProperty("yaSecret");
	}

	@Override
	public String authorize(){
		if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO,"authorize() - start");
		error=null;
		String plainUrl = "https://oauth.yandex.ru/authorize?client_id=" + yaId + "&response_type=code";

		try {
            FacesContext.getCurrentInstance().getExternalContext().redirect(plainUrl);
		} catch (UnsupportedEncodingException e1) {
			logger.severe("login encoding redirect exception!" + e1.toString());
		} catch (Exception e) {
			logger.log(Level.SEVERE, "login redirect exception!", e);
		}
		if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO,"authorize() - end");
		return "";
	}

	@Override
	public void phase2(){
		if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO,"YA Phase 2 - start");

		if (error!=null) {
            core.errorRedirect(error);
            return;
		}

		if (code != null && !code.isEmpty()){
			if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO, "code="+code);
			
			Properties props = new Properties();
			props.put("grant_type", "authorization_code");
			props.put("code", code);
			props.put("client_id", yaId);
			props.put("client_secret", yaSecret);
		    String ret1 = HttpURL.httpsPost("https://oauth.yandex.ru/token", props, "UTF-8");

			if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO, "ret1=" + ret1);

			YA ya = decodeAccessCode(ret1);

			if (logger.isLoggable(Level.INFO)) {
				logger.log(Level.INFO,"access_token=" + ya.access_token);
				logger.log(Level.INFO,"token_type="   + ya.token_type);
			}

		    String ret2 = HttpURL.httpsGet("https://login.yandex.ru/info?format=json&oauth_token="+ya.access_token);
			
			if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO,"ret2=" + ret2);

			PersonData personData = decodePersonData(ret2);
			
			if (logger.isLoggable(Level.INFO)) {
				logger.log(Level.INFO,"id="+personData.id);
				logger.log(Level.INFO,"birthday="+personData.birthday);
				logger.log(Level.INFO,"display_name="+personData.display_name);
				logger.log(Level.INFO,"sex="+personData.sex);
				logger.log(Level.INFO,"default_email="+personData.default_email);
				logger.log(Level.INFO,"real_name="+personData.real_name);
			}

			core.getUserAutoReqProps().setEmail(personData.default_email);
			if (personData.real_name!=null && !personData.real_name.isEmpty()) {
				String[] fname = personData.real_name.split(" ");
				if (fname.length>0)	core.getUserAutoReqProps().setLastName(fname[0]);
				if (fname.length>1)	core.getUserAutoReqProps().setFirstName(fname[1]);
				core.getUserAutoReqProps().setSex("male".equalsIgnoreCase(personData.sex));
			}

			try {
				DateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd");
				core.getUserAutoReqProps().setBorn(dateFormat.parse(personData.birthday));
			} catch(Exception ex) {
                logger.log(Level.WARNING, "Error:", ex);
            }

			String successURL = "http://my.ya.ru/" + personData.id;
			logger.info("success url:" + successURL);

			core.success(successURL);
		} else {
            core.errorRedirect("code is null!");
        }
		if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO,"YA Phase 2 - end");
	}

    protected YA decodeAccessCode(String json) {
        YA ya = new YA();
		JsonObject jsonObject = Json.createReader(new StringReader(json)).readObject();
		ya.access_token = JsonHelper.getStringValue(jsonObject, "access_token");
		ya.token_type   = JsonHelper.getStringValue(jsonObject, "token_type");
		return ya;
    }

    protected PersonData decodePersonData(String json) {
        PersonData personData = new PersonData();
		JsonObject jsonObject = Json.createReader(new StringReader(json)).readObject();
		personData.birthday = JsonHelper.getStringValue(jsonObject, "birthday");
		personData.display_name = JsonHelper.getStringValue(jsonObject, "display_name");
		personData.sex = JsonHelper.getStringValue(jsonObject, "sex");
		personData.id = JsonHelper.getStringValue(jsonObject, "id");
		personData.default_email = JsonHelper.getStringValue(jsonObject, "default_email");
		personData.real_name = JsonHelper.getStringValue(jsonObject, "real_name");
		personData.first_name = JsonHelper.getStringValue(jsonObject, "first_name");
		personData.last_name = JsonHelper.getStringValue(jsonObject, "last_name");
		return personData;
    }

    class YA{
        String access_token;
        String token_type;
    }

    class PersonData {
        public String birthday;
        public String display_name;
        public String sex;
        public String id;
        public String default_email;
        public String real_name;
        public String first_name;
        public String last_name;
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

	public String getState() {
		return state;
	}

	public void setState(String state) {
		this.state = state;
	}
}
