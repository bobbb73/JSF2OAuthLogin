package ua.pp.vbabich.oauth.util;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.faces.context.FacesContext;
import javax.inject.Named;
import java.io.FileInputStream;
import java.io.Serializable;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

@Named
@ApplicationScoped
public class OAuthDAO implements Serializable {

	private static final long serialVersionUID = 1L;
	private Properties prop;
	private static Logger logger = Logger.getLogger(OAuthDAO.class.getName());

	@PostConstruct
	public void initialize() {
		load();
	}

	public boolean load(){
		try (FileInputStream fis = new FileInputStream(FacesContext.getCurrentInstance().getExternalContext().getInitParameter("OAuthPropertiesPath"))){
			prop = new Properties();
			prop.load(fis);
			if (prop.isEmpty()) {
                if (logger.isLoggable(Level.WARNING)) logger.log(Level.WARNING, "OAuthDAO prop is empty!");
				return false;
			}
			if (logger.isLoggable(Level.FINEST)) logger.log(Level.FINEST,"OAuthDAO properties loaded");
		} catch (Exception ex) {
			if (logger.isLoggable(Level.WARNING)) logger.log(Level.WARNING, "OAuthDAO properties load error:" + ex.getMessage());
			return false;
		}
		return true;
	}

	public String getProperty(String key) {
		return prop.getProperty(key);
	}
}
