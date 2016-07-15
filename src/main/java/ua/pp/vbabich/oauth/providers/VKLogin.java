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
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.logging.Level;
import java.util.logging.Logger;

@Named(value="vklogin")
@RequestScoped
public class VKLogin implements OAuthProvider {

	private final static Logger logger = Logger.getLogger(VKLogin.class.getName());
	private String code;
	private String error;
	private String error_reason;
	private String error_description;
	private String parmClientId;
	private String parmRedirectURL;
	private String parmClientSecret;

	@Inject private OAuthProviders core;
	@Inject private OAuthDAO oauthDAO;

	@PostConstruct
	public void init(){
		if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO,"init()");
		if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO,"myFullContext="+core.getContextURL());
		if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO,"oauthDAO="+oauthDAO.toString());
		parmClientId = oauthDAO.getProperty("vkId");
		parmClientSecret = oauthDAO.getProperty("vkSecret");
		parmRedirectURL = core.getContextURL().concat("/pages/login/vkLogin.jsf");
	}

	@Override
	public String authorize(){
		if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO,"VK authorize() - start");
		code = null;
		String plainUrl = "http://oauth.vk.com/authorize?" +
				"client_id="+ parmClientId +
				"&scope=notify,status" +
				"&redirect_uri="+ parmRedirectURL +
				"&response_type=code";
		ExternalContext ec = FacesContext.getCurrentInstance().getExternalContext();
		try {
			ec.redirect(plainUrl);
		} catch (UnsupportedEncodingException e1) {
			logger.severe("login encoding redirect exception!" + e1.toString());
		} catch (Exception e) {
			logger.severe("login redirect exception!" + e.toString());
		}
		if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO,"VK authorize() - end");
		return "";
	}

	@Override
	public void phase2(){
		if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO,"VK Phase 2");
		if (code != null && !code.isEmpty()){
			if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO,"VK Phase 2 Login code="+code);
			String accessTokenURL = "https://oauth.vk.com/access_token?" +
					"client_id="+ parmClientId +
					"&client_secret="+ parmClientSecret +
					"&code="+code +
					"&redirect_uri="+parmRedirectURL;
			if (logger.isLoggable(Level.INFO)) {
				logger.log(Level.INFO,"VK Phase 2 accessTokenURL="+accessTokenURL);
				logger.log(Level.INFO,"VK Phase 2 Send request to VK.com");
			}

		    String ret = HttpURL.httpsGet(accessTokenURL);
		    if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO,"VK Phase 2 response:"+ret);

		    VK vk = decodeResponse(ret);
			if (logger.isLoggable(Level.INFO)) {
				logger.log(Level.INFO,"VK Phase 2 access_token=" + vk.access_token);
				logger.log(Level.INFO,"VK Phase 2 user_id=" + vk.user_id);
				logger.log(Level.INFO,"VK Phase 2 expires_in=" + vk.expires_in);
				logger.log(Level.INFO,"VK Phase 2 error=" + vk.error);
				logger.log(Level.INFO,"VK Phase 2 info=" + vk.info);
			}

			String ret1 = HttpURL.httpsGet("https://api.vk.com/method/users.get?uids="+vk.user_id +
					"&fields=uid,first_name,last_name,nickname,screen_name,sex,bdate,city,country,timezone,photo" +
					"&access_token="+vk.access_token);
			if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO,"VK Phase 2 ret1="+ret1);

			try {
				Info info = decodeInfo(ret1);
				core.getUserAutoReqProps().setFirstName(info.first_name);
				core.getUserAutoReqProps().setLastName(info.last_name);
				core.getUserAutoReqProps().setSex(info.sex==2);
				DateFormat dateFormat = new SimpleDateFormat("dd.MM.yyyy");
				core.getUserAutoReqProps().setBorn(dateFormat.parse(info.bdate));
			}catch(Exception ex){
				logger.log(Level.WARNING, "Error:", ex);
			}
            core.success("http://vk.com/id".concat(vk.user_id.toString()));
		} else {
			logger.severe("Login error="+error);
			logger.severe("Login error_reason="+error_reason);
			logger.severe("Login error_description="+error_description);
            core.errorRedirect(error);
		}
	}

    protected Info decodeInfo(String json) {
        Info info = new Info();
        JsonReader jsonReader = Json.createReader(new StringReader(json));
        JsonObject jsonObject = jsonReader.readObject().getJsonArray("response").getJsonObject(0);
        info.first_name = jsonObject.getString("first_name");
        info.last_name = jsonObject.getString("last_name");
        info.sex = jsonObject.getInt("sex");
        info.bdate = jsonObject.getString("bdate");
        return info;
    }

    protected VK decodeResponse(String json) {
		VK vk = new VK();
        JsonReader jsonReader = Json.createReader(new StringReader(json));
        JsonObject jsonObject = jsonReader.readObject();
        vk.access_token = jsonObject.getString("access_token");
        vk.expires_in = jsonObject.getInt("expires_in");
        vk.user_id = jsonObject.getInt("user_id");
        return vk;
	}

	class Info {
		public String uid;
		public String first_name;
		public String last_name;
		public int sex;
		public String nickname;
		public String screen_name;
		public String bdate;
		public String city;
		public String country;
		public String timezone;
		public String photo;
	}

	class VK{
		String access_token;
		Integer expires_in;
		Integer user_id;
		String error;
		String info;
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

	public String getError_description() {
		return error_description;
	}

	public void setError_description(String error_description) {
		this.error_description = error_description;
	}

	public String getError_reason() {
		return error_reason;
	}

	public void setError_reason(String error_reason) {
		this.error_reason = error_reason;
	}
}
