package ua.pp.vbabich.oauth.providers;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class MRLoginTest {

    @Test
    public void testDecodeToken() throws Exception {
        String json = "{\"expires_in\":86400,\"refresh_token\":\"0e148b5f71e0749451545e048f6a7daf\",\"access_token\":\"728cfcbe6ee0b770aeb1a6b824d05c5f\",\"token_type\":\"bearer\",\"x_mailru_vid\":\"5997306673588032511\"}";
        MRLogin target = new MRLogin();
        MRLogin.MR mr = target.decodeToken(json);

        assertEquals("728cfcbe6ee0b770aeb1a6b824d05c5f", mr.access_token);
        assertEquals("0e148b5f71e0749451545e048f6a7daf", mr.refresh_token);
        assertEquals((Integer)86400, mr.expires_in);
    }

    @Test
    public void testDecodePersonData() throws Exception {
        String json = "[{\"pic_50\":\"http://avt-3.foto.mail.ru/mail/vladimir_babich/_avatar50\",\"video_count\":0,\"friends_count\":0,\"show_age\":1,\"nick\":\"\",\"is_friend\":0,\"is_online\":1,\"email\":\"vladimir_babich@mail.ru\",\"has_pic\":0,\"follower\":0,\"pic_190\":\"http://avt-8.foto.mail.ru/mail/vladimir_babich/_avatar190\",\"referer_id\":\"\",\"app_count\":{\"web\":0,\"mob_web\":0},\"following\":0,\"pic_32\":\"http://avt-7.foto.mail.ru/mail/vladimir_babich/_avatar32\",\"referer_type\":\"\",\"last_visit\":\"1457337326\",\"uid\":\"5997306673588032511\",\"app_installed\":1,\"status_text\":\"\",\"pic_22\":\"http://avt-26.foto.mail.ru/mail/vladimir_babich/_avatar22\",\"has_my\":1,\"age\":43,\"last_name\":\"Babich\",\"is_verified\":0,\"pic_big\":\"http://avt-18.foto.mail.ru/mail/vladimir_babich/_avatarbig\",\"vip\":0,\"birthday\":\"16.03.1973\",\"link\":\"http://my.mail.ru/mail/vladimir_babich/\",\"pic_128\":\"http://avt-23.foto.mail.ru/mail/vladimir_babich/_avatar128\",\"sex\":0,\"pic\":\"http://avt-8.foto.mail.ru/mail/vladimir_babich/_avatar\",\"pic_small\":\"http://avt-2.foto.mail.ru/mail/vladimir_babich/_avatarsmall\",\"pic_180\":\"http://avt-25.foto.mail.ru/mail/vladimir_babich/_avatar180\",\"first_name\":\"Vladimir\",\"pic_40\":\"http://avt-4.foto.mail.ru/mail/vladimir_babich/_avatar40\"}]";
        MRLogin target = new MRLogin();
        MRLogin.PersonData personData = target.decodePersonData(json);

        assertEquals("Vladimir", personData.first_name);
        assertEquals("Babich", personData.last_name);
        assertEquals("16.03.1973", personData.birthday);
        assertEquals("vladimir_babich@mail.ru", personData.email);
        assertEquals("http://my.mail.ru/mail/vladimir_babich/", personData.link);
        assertEquals("", personData.nick);
        assertEquals("5997306673588032511", personData.uid);
        assertEquals((Integer)0, personData.sex);
    }
}