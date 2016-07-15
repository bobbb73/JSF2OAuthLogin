package ua.pp.vbabich.oauth.providers;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class GooLoginTest {

    @Test
    public void testDecodePayload() throws Exception {
        String json = "{  \"access_token\" : \"ya29.Ci8fA95Zj6Q1ekCvvehf28eeilZQxP8UkLorNCEjjGy5H5ggcKPta4-p06_9qXSiiA\",  \"token_type\" : \"Bearer\",  \"expires_in\" : 3600,  \"id_token\" : \"eyJhbGciOiJSUzI1NiIsImtpZCI6ImVhZjg0YmRiZWVjMDIzNzU3NTVmOTIyY2U2OWRkMGVkYmFkODFkNzUifQ.eyJpc3MiOiJhY2NvdW50cy5nb29nbGUuY29tIiwiYXRfaGFzaCI6ImFGOUpJeHVLOW8tSk9xYkE0T3dhLUEiLCJhdWQiOiI0NDQ2OTg1NTMxMzAuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDUzOTc5NjQxMDQ4OTM4MTQyNjEiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiYXpwIjoiNDQ0Njk4NTUzMTMwLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwiZW1haWwiOiJiYWJpY2gya0BnbWFpbC5jb20iLCJpYXQiOjE0Njg0MTY2MTgsImV4cCI6MTQ2ODQyMDIxOH0.Xfd7wMtE3yzgFzAA1mnmth3kc5f_cHyXlLhAvQHbPHtCc-VSU0HOUJ0rMGmzLFyS1H3qOTuHs4sYGHgrrlYydzX9eyy_fjbJy0D_zQvmRtoDPk9Oz-uF0KMZhBypM_9Iv6GmpGWGrcbhJkMUF5gvfBx8LhxmAdEkHS_h0DwRmhrxS5UkvnJpnkvTft9KwEYsqNCFv20bivN_UZSkxhzvNyZueX-vp4EQ7YnmQPF0HTna1oCYZAPpqqdggtNS1g4YIYFuWDzYVScMJBN_Qr4L5VmDm9XhPpIVdm16WA_ZZ9X4zz3x07TZD-RoqcaU2lvkp7kH2NBMdINh0z4Cs8u_rQ\"}";
        GooLogin target = new GooLogin();

        GooLogin.TokensPayload tp = target.decodePayload(json);

        assertEquals("ya29.Ci8fA95Zj6Q1ekCvvehf28eeilZQxP8UkLorNCEjjGy5H5ggcKPta4-p06_9qXSiiA", tp.access_token);
        assertEquals("eyJhbGciOiJSUzI1NiIsImtpZCI6ImVhZjg0YmRiZWVjMDIzNzU3NTVmOTIyY2U2OWRkMGVkYmFkODFkNzUifQ.eyJpc3MiOiJhY2NvdW50cy5nb29nbGUuY29tIiwiYXRfaGFzaCI6ImFGOUpJeHVLOW8tSk9xYkE0T3dhLUEiLCJhdWQiOiI0NDQ2OTg1NTMxMzAuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDUzOTc5NjQxMDQ4OTM4MTQyNjEiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiYXpwIjoiNDQ0Njk4NTUzMTMwLmFwcHMuZ29vZ2xldXNlcmNvbnRlbnQuY29tIiwiZW1haWwiOiJiYWJpY2gya0BnbWFpbC5jb20iLCJpYXQiOjE0Njg0MTY2MTgsImV4cCI6MTQ2ODQyMDIxOH0.Xfd7wMtE3yzgFzAA1mnmth3kc5f_cHyXlLhAvQHbPHtCc-VSU0HOUJ0rMGmzLFyS1H3qOTuHs4sYGHgrrlYydzX9eyy_fjbJy0D_zQvmRtoDPk9Oz-uF0KMZhBypM_9Iv6GmpGWGrcbhJkMUF5gvfBx8LhxmAdEkHS_h0DwRmhrxS5UkvnJpnkvTft9KwEYsqNCFv20bivN_UZSkxhzvNyZueX-vp4EQ7YnmQPF0HTna1oCYZAPpqqdggtNS1g4YIYFuWDzYVScMJBN_Qr4L5VmDm9XhPpIVdm16WA_ZZ9X4zz3x07TZD-RoqcaU2lvkp7kH2NBMdINh0z4Cs8u_rQ", tp.id_token);
        assertEquals("Bearer", tp.token_type);
        assertEquals((Integer)3600, tp.expires_in);
    }

    @Test
    public void testDecodeClaims() throws Exception {
        String json = "{\"iss\":\"accounts.google.com\",\"at_hash\":\"aF9JIxuK9o-JOqbA4Owa-A\",\"aud\":\"444698553130.apps.googleusercontent.com\",\"sub\":\"105397964104893814261\",\"email_verified\":true,\"azp\":\"444698553130.apps.googleusercontent.com\",\"email\":\"babich2k@gmail.com\",\"iat\":1468416618,\"exp\":1468420218}";
        GooLogin target = new GooLogin();

        GooLogin.Claims claims = target.decodeClaims(json);

        assertEquals("aF9JIxuK9o-JOqbA4Owa-A", claims.at_hash);
        assertEquals("444698553130.apps.googleusercontent.com", claims.aud);
        assertEquals("444698553130.apps.googleusercontent.com", claims.azp);
        assertEquals("babich2k@gmail.com", claims.email);
        assertEquals("accounts.google.com", claims.iss);
        assertEquals("105397964104893814261", claims.sub);
        assertTrue(claims.email_verified);
        assertEquals((Integer)1468420218, claims.exp);
        assertEquals((Integer)1468416618, claims.iat);
    }

    @Test
    public void testDecodePersonData() throws Exception {
        String json = "{ \"id\": \"105397964104893814261\", \"email\": \"babich2k@gmail.com\", \"verified_email\": true, \"name\": \"Володимир Бабич\", \"given_name\": \"Володимир\", \"family_name\": \"Бабич\", \"link\": \"https://plus.google.com/105397964104893814261\", \"picture\": \"https://lh6.googleusercontent.com/-zxW4IxTZApM/AAAAAAAAAAI/AAAAAAAAACo/Hx8A3ktU7rY/photo.jpg\", \"gender\": \"male\", \"locale\": \"uk\"}";
        GooLogin target = new GooLogin();

        GooLogin.PersonData personData = target.decodePersonData(json);

        assertEquals("105397964104893814261", personData.id);
        assertEquals("babich2k@gmail.com", personData.email);
        assertEquals("Бабич", personData.family_name);
        assertEquals("male", personData.gender);
        assertEquals("Володимир", personData.given_name);
        assertEquals("https://plus.google.com/105397964104893814261", personData.link);
        assertEquals("uk", personData.locale);
        assertEquals("Володимир Бабич", personData.name);
        assertEquals("https://lh6.googleusercontent.com/-zxW4IxTZApM/AAAAAAAAAAI/AAAAAAAAACo/Hx8A3ktU7rY/photo.jpg", personData.picture);
        assertTrue(personData.verified_email);
    }
}