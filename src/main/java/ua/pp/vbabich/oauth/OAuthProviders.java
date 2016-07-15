package ua.pp.vbabich.oauth;

import ua.pp.vbabich.oauth.model.UserAutoReqProps;

import javax.annotation.PostConstruct;
import javax.enterprise.context.SessionScoped;
import javax.enterprise.inject.spi.CDI;
import javax.inject.Named;
import java.io.Serializable;
import java.util.logging.Level;
import java.util.logging.Logger;

@Named
@SessionScoped
public class OAuthProviders implements Serializable {

    private static Logger logger = Logger.getLogger(OAuthProviders.class.getName());

    private String state;
    private UserAutoReqProps userAutoReqProps;
    private OAuthCallbackIntf callback;
    private String contextURL;

    @PostConstruct
    protected void initialize(){
        userAutoReqProps = new UserAutoReqProps();
    }

    public void authorize(String providerName) {
        if ( callback == null ) {
            logger.warning("Error: callback handler is not set!");
            return;
        }
        OAuthProvider provider = CDI.current().select(Providers.getProvider(providerName)).get();
        provider.authorize();
    }

    public void errorRedirect(String error){
        if (logger.isLoggable(Level.INFO)) logger.log(Level.INFO, "error=" + error);
        callback.onError(error);
    }

    public void success(String validatedId){
        callback.onSuccess(validatedId, userAutoReqProps);
    }

    public void setState(String state) {
        this.state = state;
    }

    public String getState() {
        return state;
    }

    public UserAutoReqProps getUserAutoReqProps() {
        return userAutoReqProps;
    }

    public void setCallback(OAuthCallbackIntf callback) {
        this.callback = callback;
    }

    public void setContextURL(String contextURL) {
        this.contextURL = contextURL;
    }

    public String getContextURL() {
        return contextURL;
    }
}
