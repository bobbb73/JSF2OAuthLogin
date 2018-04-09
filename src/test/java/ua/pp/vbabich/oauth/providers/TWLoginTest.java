package ua.pp.vbabich.oauth.providers;

import junit.framework.TestCase;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import ua.pp.vbabich.oauth.OAuthProviders;
import ua.pp.vbabich.oauth.util.OAuthDAO;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;
import java.util.stream.Collectors;

import static org.mockito.Mockito.when;
import static ua.pp.vbabich.oauth.providers.TWLogin.percentEncode;

@RunWith(MockitoJUnitRunner.class)
public class TWLoginTest extends TestCase {

	@Mock
	private OAuthProviders core;

	@Mock
	private OAuthDAO oauthDAO;

	@InjectMocks
	private TWLogin twLogin = new TWLogin();

	@Test
	@Ignore
	public void testAuthorize() {

		when(oauthDAO.getProperty("twConsumerKey")).thenReturn("w5LWbVUIhvhm80Pt6EqoZIt9I");
		when(oauthDAO.getProperty("twConsumerSecret")).thenReturn("zgfInGp0C011HevtlYZVgDrM7PyoS0LbaaynnUtJdDe5RKXS7G");
		when(oauthDAO.getProperty("twRequestTokenURL")).thenReturn("https://api.twitter.com/oauth/request_token");
		when(oauthDAO.getProperty("twAuthorizeURL")).thenReturn("https://api.twitter.com/oauth/authorize");
		when(oauthDAO.getProperty("twAccessTokenURL")).thenReturn("https://api.twitter.com/oauth/access_token");
		when(oauthDAO.getProperty("twCallbackURL")).thenReturn("https://www.vbabich.pp.ua/JSF2OAuthLogin/pages/login/twLogin.jsf");
		when(oauthDAO.getProperty("twEnabled")).thenReturn("true");

		twLogin.init();
		String result = twLogin.authorize();
		assertNotNull(result);
	}

	@Test
	public void testPhase2() {
	}

	@Test
	@Ignore
	public void computeSignatureTest() throws InvalidKeyException, NoSuchAlgorithmException {
		StringBuilder sb = new StringBuilder();
		sb.append("oauth_consumer_key=").append("cChZNFj6T5R0TigYB9yd1w");
		sb.append("&oauth_nonce=").append("ea9ec8429b68d6b77cd5600adbbb0456");
		sb.append("&oauth_signature_method=").append("HMAC-SHA1");
		sb.append("&oauth_timestamp=").append("1318467427");
		sb.append("&oauth_version=").append("1.0");

		String signature = percentEncode(twLogin.computeSignature(//"POST&" +
				"http://localhost/sign-in-with-twitter/" +
						"&" +
						sb.toString(), "L8qq9PZyRg6ieKGEKhZolGC0vJWLw8iEJ88DRdyOg"));
		assertEquals("F1Li3tvehgcraF8DMJ7OyxO4w9Y%3D", signature);
	}

	@Test
	public void computeSignatureOriginTest() throws InvalidKeyException, NoSuchAlgorithmException {

		String url = "https://api.twitter.com/1.1/statuses/update.json";
		String consumerSecret = "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw";
		String oAuthTokenSecret = "LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE";

		Map<String, String> params = new HashMap<>();
		params.put("status", "Hello Ladies + Gentlemen, a signed OAuth request!");
		params.put("include_entities", "true");
		params.put("oauth_consumer_key", "xvz1evFS4wEEPTGEFPHBog");
		params.put("oauth_nonce", "kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg");
		params.put("oauth_signature_method", "HMAC-SHA1");
		params.put("oauth_timestamp", "1318622958");
		params.put("oauth_token", "370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb");
		params.put("oauth_version", "1.0");

		Map<String, String> encodedParams = new HashMap<>();
		params.forEach((k, v) -> encodedParams.put(percentEncode(k), percentEncode(v)));
		Map<String, String> sortedEncodedParams = new TreeMap<String, String>(encodedParams);

		String parameterString = sortedEncodedParams.entrySet().stream()
				.map(e -> e.getKey() + "=" + e.getValue())
				.collect(Collectors.joining("&"));

		String originalParameterString = "include_entities=true&oauth_consumer_key=xvz1evFS4wEEPTGEFPHBog&oauth_nonce=kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1318622958&oauth_token=370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb&oauth_version=1.0&status=Hello%20Ladies%20%2B%20Gentlemen%2C%20a%20signed%20OAuth%20request%21";
		assertEquals(originalParameterString, parameterString);

		StringBuilder sb = new StringBuilder();
		sb.append("POST");
		sb.append('&');
		sb.append(percentEncode(url));
		sb.append('&');
		sb.append(percentEncode(originalParameterString));

		String originalSignatureBaseString = "POST&https%3A%2F%2Fapi.twitter.com%2F1.1%2Fstatuses%2Fupdate.json&include_entities%3Dtrue%26oauth_consumer_key%3Dxvz1evFS4wEEPTGEFPHBog%26oauth_nonce%3DkYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1318622958%26oauth_token%3D370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb%26oauth_version%3D1.0%26status%3DHello%2520Ladies%2520%252B%2520Gentlemen%252C%2520a%2520signed%2520OAuth%2520request%2521";
		assertEquals(originalSignatureBaseString, sb.toString());

		String oAuthSignature = twLogin.computeSignature(sb.toString(), consumerSecret + "&" + oAuthTokenSecret);
		String originalOAuthSignature = "hCtSmYh+iHYCEqBWrE7C7hYmtUk=";
		assertEquals(originalOAuthSignature, oAuthSignature);
	}
}