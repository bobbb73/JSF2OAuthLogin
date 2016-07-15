package ua.pp.vbabich.oauth.providers;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class LILoginTest {

    @Test
    public void testDecodeToken() throws Exception {
        String json = "{\"access_token\":\"AQWKxYRriu8k2_eTyuR4SXACrhip3cJOYH_NGF0ABdEe-YAgTj1sFlvU7J6Q3Ob8VtDFnWYhbM1BIpsui-AyYOFMNmor5_q_tZhc6ZpxcdPHB8_6jJI-dEatH430kMYfgha5cVWMXP_EvsQa0a_eRA094XUZS03yOViraxv4eunG6sddDz0\",\"expires_in\":5183999}";
        LILogin target = new LILogin();

        LILogin.Token token = target.decodeToken(json);

        assertEquals("AQWKxYRriu8k2_eTyuR4SXACrhip3cJOYH_NGF0ABdEe-YAgTj1sFlvU7J6Q3Ob8VtDFnWYhbM1BIpsui-AyYOFMNmor5_q_tZhc6ZpxcdPHB8_6jJI-dEatH430kMYfgha5cVWMXP_EvsQa0a_eRA094XUZS03yOViraxv4eunG6sddDz0", token.access_token);
        assertEquals((Integer)5183999, token.expires_in);
    }
}