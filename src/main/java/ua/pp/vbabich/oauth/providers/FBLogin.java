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
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

@Named(value="fblogin")
@RequestScoped
public class FBLogin implements OAuthProvider {

	private final static Logger logger = Logger.getLogger(FBLogin.class.getName());
	private String code;
	private String state;
	private String error;
	private String error_reason;
	private String error_description;
	private String parmAppId;
	private String parmRedirectURL;
	private String parmAppSecret;

	@Inject private OAuthProviders core;
	@Inject private OAuthDAO oauthDAO;

	@PostConstruct
	public void init(){
		parmAppId = oauthDAO.getProperty("fbId");
		parmAppSecret = oauthDAO.getProperty("fbSecret");
		parmRedirectURL = core.getContextURL().concat("/pages/login/fbLogin.jsf");
	}

	@Override
	public String authorize(){
		if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO,"FB authorize() - start");
		code = null;
		core.setState(UUID.randomUUID().toString().replaceAll("-", ""));
		String plainUrl = "https://www.facebook.com/dialog/oauth?client_id="+ parmAppId +"&scope=user_about_me,user_status&redirect_uri="+ parmRedirectURL + "&state=" + core.getState();
		if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO,"authorize() plainUrl="+plainUrl);

		try {
			FacesContext.getCurrentInstance().getExternalContext().redirect(plainUrl);
		} catch (Exception e) {
			logger.log(Level.SEVERE,"login redirect exception!" + e);
		}
		if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO,"FB authorize() - end");
		return null;
	}

	@Override
	public void phase2(){
		if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO,"FB Phase 2");
		if (logger.isLoggable(Level.FINE)) logger.log(Level.FINE, "code=" + code + " state=" + state + " error=" + error + " error_reason=" + error_reason + " error_description=" + error_description);
		if (code != null && !code.isEmpty()) {
			if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO,"code="+code);
			if (!core.getState().equals(state)) {
				logger.log(Level.SEVERE, "phase2() myState!=state");
				logger.log(Level.SEVERE, "phase2() myState="+core.getState());
				logger.log(Level.SEVERE, "phase2() state="+state);
				return;
			}
		    String ret = HttpURL.httpsGet("https://graph.facebook.com/oauth/access_token?client_id=" + parmAppId + "&redirect_uri=" + parmRedirectURL + "&client_secret=" + parmAppSecret + "&code="+code);

		    if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO,"phase2() ret="+ret);

			Map<String, String> parms = parse(ret);		// Здесь может быть не строка а JSON с ошибками!
			String accessToken = parms.get("access_token");
			String expires = parms.get("expires");

			if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO,"access_token=" + accessToken + " expires=" + expires);
			ret = HttpURL.httpsGet("https://graph.facebook.com/me?access_token="+accessToken);

		    if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO,"fb 2 response:"+ret);
		    
			FB fb = decodeResponse(ret);
		    if (logger.isLoggable(Level.INFO)) {
                logger.log(Level.INFO,"firstName=" + fb.first_name);
		        logger.log(Level.INFO,"lastName=" + fb.last_name);
		        logger.log(Level.INFO,"userId=" + fb.id);
		        logger.log(Level.INFO,"link=" + fb.link);
            }

            // Передаем полученные данные для регистрации
            core.getUserAutoReqProps().setFirstName(fb.first_name);
            core.getUserAutoReqProps().setLastName(fb.last_name);
			core.success(fb.link);
		} else {
			logger.severe("Login error="+error);
			logger.severe("Login error_reason="+error_reason);
			logger.severe("Login error_description="+error_description);
			try {
				FacesContext.getCurrentInstance().getExternalContext().redirect("/");
			} catch (Exception ex) {
				logger.log(Level.SEVERE, "phase2 Error2: redirect failed!", ex);
			}
		}
	}

    protected FB decodeResponse(String json){
        FB fb = new FB();
		JsonReader jsonReader = Json.createReader(new StringReader(json));
		JsonObject jsonObject = jsonReader.readObject();
		fb.first_name = jsonObject.getString("first_name");
        fb.last_name = jsonObject.getString("last_name");
        fb.name = jsonObject.getString("name");
        fb.id = jsonObject.getString("id");
        fb.link = jsonObject.getString("link");
        return fb;
    }

    protected Map<String,String> parse(String str){
		Map<String,String> map = new HashMap<>(2);
		String[] items = str.split("&");
		for(String item: items){
			String[] arr = item.split("=");
			if (arr.length>1 && arr[0] != null && arr[1] != null)
				map.put(arr[0], arr[1]);
		}
		return map;
	}

	public String getCode() {
		return code;
	}

    class FB{
        String first_name;
        String last_name;
        String id;
        String link;
        String name;
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

	public String getState() {
		return state;
	}

	public void setState(String state) {
		this.state = state;
	}
}
