package ua.pp.vbabich.oauth.providers;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class YALoginTest {

    @Test
    public void testDecodeAccessCode() throws Exception {
        String json = "{\"token_type\": \"bearer\", \"access_token\": \"AQAAAAAJR0AFAAHGOkKcWgwArU1GscjMW5lc9S0\", \"expires_in\": 31536000}";
        YALogin destination = new YALogin();

        YALogin.YA ya = destination.decodeAccessCode(json);

        assertEquals(ya.access_token, "AQAAAAAJR0AFAAHGOkKcWgwArU1GscjMW5lc9S0");
        assertEquals(ya.token_type, "bearer");
    }

    @Test
    public void testDecodePersonData() throws Exception {
        String json = "{\"first_name\": \"\\u0412\\u043e\\u043b\\u043e\\u0434\\u0438\\u043c\\u0438\\u0440\", \"last_name\": \"\\u0411\\u0430\\u0431\\u0438\\u0447\", \"display_name\": \"\\u0412\\u043b\\u0430\\u0434\\u0438\\u043c\\u0438\\u0440 \\u0411\\u0430\\u0431\\u0438\\u0447\", \"emails\": [\"bobbb73@yandex.ua\"], \"default_email\": \"bobbb73@yandex.ua\", \"real_name\": \"\\u0412\\u043e\\u043b\\u043e\\u0434\\u0438\\u043c\\u0438\\u0440 \\u0411\\u0430\\u0431\\u0438\\u0447\", \"birthday\": \"1973-03-16\", \"login\": \"bobbb73\", \"sex\": \"male\", \"id\": \"155664389\"}";
        YALogin destination = new YALogin();

        YALogin.PersonData personData = destination.decodePersonData(json);

        assertEquals("Володимир", personData.first_name);
        assertEquals("Бабич", personData.last_name);
        assertEquals("Владимир Бабич", personData.display_name);
        assertEquals("bobbb73@yandex.ua", personData.default_email);
        assertEquals("male", personData.sex);
        assertEquals("1973-03-16", personData.birthday);
        assertEquals("155664389", personData.id);
    }
}