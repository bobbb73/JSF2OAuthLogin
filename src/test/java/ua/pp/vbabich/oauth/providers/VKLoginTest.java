package ua.pp.vbabich.oauth.providers;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class VKLoginTest {

    @Test
    public void decodeResponse() throws Exception {

        String json = "{\"access_token\":\"f233e735cc07fb8954fadbf4c890c5ac29e16ef26478cb7bc8eada0dc5b3a3b68cd4b4aeaef22b367e9a8\",\"expires_in\":86400,\"user_id\":61107722}";

        VKLogin destination = new VKLogin();
        VKLogin.VK vk = destination.decodeResponse(json);

        assertEquals("f233e735cc07fb8954fadbf4c890c5ac29e16ef26478cb7bc8eada0dc5b3a3b68cd4b4aeaef22b367e9a8", vk.access_token);
        assertEquals((Integer)86400, vk.expires_in);
        assertEquals((Integer)61107722, vk.user_id);
    }

    @Test
    public void decodeInfo() throws Exception {

        String json = "{\"response\":[{\"uid\":61107722,\"first_name\":\"Володимир\",\"last_name\":\"Бабич\",\"sex\":2,\"nickname\":\"\",\"screen_name\":\"babich2k\",\"bdate\":\"16.3.1973\",\"city\":314,\"country\":2,\"timezone\":3,\"photo\":\"http:\\/\\/cs9520.vk.me\\/u61107722\\/e_1927c06c.jpg\"}]}";

        VKLogin destination = new VKLogin();
        VKLogin.Info info = destination.decodeInfo(json);

        assertEquals("Володимир", info.first_name);
        assertEquals("Бабич", info.last_name);
        assertEquals(2, info.sex);
        assertEquals("16.3.1973", info.bdate);
    }

}