package ua.pp.vbabich.oauth;

public interface OAuthProvider {
    String authorize();
    void phase2();
}
