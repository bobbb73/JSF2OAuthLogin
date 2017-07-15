package ua.pp.vbabich.oauth.util;

import javax.json.JsonObject;
import java.util.logging.Level;
import java.util.logging.Logger;

public class JsonHelper {
	private static final Logger logger = Logger.getLogger(JsonHelper.class.getCanonicalName());

	public static String getStringValue(JsonObject jsonObject, String name){
		try {
			return jsonObject.getString(name);
		} catch (Exception ex) {
			if (logger.isLoggable(Level.WARNING))
				logger.log(Level.WARNING, "Error read \"" + name + "\" value");
		}
		return null;
	}

	public static String getStringValue(JsonObject jsonObject, String name, String deflt){
		String res = getStringValue(jsonObject, name);
		if (res == null) return deflt;
		return res;
	}

	public static int getIntValue(JsonObject jsonObject, String name){
		try {
			return jsonObject.getInt(name);
		} catch (Exception ex) {
			if (logger.isLoggable(Level.WARNING))
				logger.log(Level.WARNING, "Error read \""+name+"\" value");
		}
		return 0;
	}

	public static int getIntValue(JsonObject jsonObject, String name, int deflt) {
		try {
			return jsonObject.getInt(name);
		} catch (Exception ex) {
			if (logger.isLoggable(Level.WARNING))
				logger.log(Level.WARNING, "Error read \""+name+"\" value");
		}
		return deflt;
	}

	public static Boolean getBooleanValue(JsonObject jsonObject, String name){
		try {
			return jsonObject.getBoolean(name);
		} catch (Exception ex) {
			if (logger.isLoggable(Level.WARNING))
				logger.log(Level.WARNING, "Error read \""+name+"\" value");
		}
		return null;
	}
}
