package ua.pp.vbabich.oauth;

import ua.pp.vbabich.oauth.model.UserAutoReqProps;

public interface OAuthCallbackIntf {
    void onSuccess(String validatedId, UserAutoReqProps userAutoReqProps);
    void onError(String error);
}
