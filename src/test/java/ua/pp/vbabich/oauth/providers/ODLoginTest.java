package ua.pp.vbabich.oauth.providers;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class ODLoginTest {

    @Test
    public void testByteArrayToHex() throws Exception {
        ODLogin odLogin = new ODLogin();
        String orig = "000102030405060708090a0b0c0d0e0f" +
                "101112131415161718191a1b1c1d1e1f" +
                "202122232425262728292a2b2c2d2e2f" +
                "303132333435363738393a3b3c3d3e3f" +
                "404142434445464748494a4b4c4d4e4f" +
                "505152535455565758595a5b5c5d5e5f" +
                "606162636465666768696a6b6c6d6e6f" +
                "707172737475767778797a7b7c7d7e7f" +
                "808182838485868788898a8b8c8d8e8f" +
                "909192939495969798999a9b9c9d9e9f" +
                "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf" +
                "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf" +
                "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf" +
                "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf" +
                "e0e1e2e3e4e5e6e7e8e9eaebecedeeef" +
                "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
        byte[] hex = new byte[256];
        for(int i = 0; i<=0xff; i++){
            hex[i] = (byte) i;
        }
        String hexString = odLogin.byteArrayToHex(hex);
        assertEquals(orig, hexString);
    }

    @Test
    public void decodeAccessTest(){
        String json = "{\"access_token\":\"f3ipa.1w3900402z3u65n3o3k71srvg465\",\"refresh_token\":\"b85964382941_a4bf0a9c1d6f9cc4d3c7e8bde0596a1f_56142105676c\",\"expires_in\":\"1800\"}";
        ODLogin destination = new ODLogin();

        ODLogin.OD od = destination.decodeAccess(json);

        assertEquals("f3ipa.1w3900402z3u65n3o3k71srvg465", od.access_token);
        assertEquals("b85964382941_a4bf0a9c1d6f9cc4d3c7e8bde0596a1f_56142105676c", od.refresh_token);
    }

    @Test
    public void decodePersonDataTest(){
        String json = "{\"uid\":\"561421056768\",\"birthday\":\"1973-03-16\",\"age\":43,\"name\":\"Володимир Бабич\",\"locale\":\"uk\",\"gender\":\"male\",\"location\":{\"city\":\"Київ\",\"country\":\"UKRAINE\",\"countryCode\":\"UA\",\"countryName\":\"Україна\"},\"online\":\"web\",\"first_name\":\"Володимир\",\"last_name\":\"Бабич\",\"has_email\":true,\"photo_id\":\"489517123840\",\"pic_1\":\"http://i500.mycdn.me/image?id=489517123840&bid=489517123840&t=32&plc=API&viewToken=Exox5JfDfxAlQPyDsnxG9g&aid=189424640&tkn=*xsaSvZvO8URVvwsSMPLLcvH1UzI\",\"pic_2\":\"http://usd1.mycdn.me/image?id=489517123840&bid=489517123840&t=2&plc=API&viewToken=Exox5JfDfxAlQPyDsnxG9g&aid=189424640&tkn=*4S6okFDfM3eXJ8hZdlsZ7KvAx8E\",\"pic_3\":\"http://i500.mycdn.me/image?id=489517123840&bid=489517123840&t=33&plc=API&viewToken=Exox5JfDfxAlQPyDsnxG9g&aid=189424640&tkn=*vbXo5QDUvs_Jdqgp1x0DFC4lnH8\"}";
        ODLogin destination = new ODLogin();

        ODLogin.PersonData personData = destination.decodePersonData(json);

        assertEquals("Бабич", personData.last_name);
        assertEquals("Володимир", personData.first_name);
        assertEquals("male", personData.gender);
        assertEquals("1973-03-16", personData.birthday);
        assertEquals("561421056768", personData.uid);
        assertEquals((Integer)43, personData.age);
    }

}