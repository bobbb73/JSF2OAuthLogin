package ua.pp.vbabich.oauth;

import ua.pp.vbabich.oauth.providers.*;

public enum Providers {

    FBLOGIN(FBLogin.class),
    GOOLOGIN(GooLogin.class),
    LILOGIN(LILogin.class),
    MRLOGIN(MRLogin.class),
    ODLOGIN(ODLogin.class),
    TWLOGIN(TWLogin.class),
    VKLOGIN(VKLogin.class),
    YALOGIN(YALogin.class);

    private Class<OAuthProvider> aClass;

    Providers(Class aClass){
        this.aClass = aClass;
    }

    public static Class<OAuthProvider> getProvider(String name){
        return Providers.valueOf(name).aClass;
    }
}
