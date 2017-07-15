package ua.pp.vbabich.oauth.util;

import org.junit.Test;

import javax.json.Json;
import javax.json.JsonObject;
import java.io.StringReader;

import static org.junit.Assert.*;

public class JsonHelperTest {

	@Test
	public void testGetStringValue() throws Exception {
		String json="{\"key\":\"value\"}";
		JsonObject jsonObject = Json.createReader(new StringReader(json)).readObject();
		String value= JsonHelper.getStringValue(jsonObject, "key");
		assertEquals(value, "value");
	}

	@Test
	public void testGetStringValueDef() throws Exception {
		String json="{\"key\":\"value\"}";
		String defValue = "22";
		JsonObject jsonObject = Json.createReader(new StringReader(json)).readObject();
		String value= JsonHelper.getStringValue(jsonObject, "key22", defValue);
		assertEquals(value, defValue);

	}

	@Test
	public void testGetIntValue() throws Exception {
		String json="{\"key\":22}";
		JsonObject jsonObject = Json.createReader(new StringReader(json)).readObject();
		int value= JsonHelper.getIntValue(jsonObject, "key");
		assertEquals(value, 22);
	}

	@Test
	public void testGetIntValueDef() throws Exception {
		String json="{\"key\":33}";
		int def = 22;
		JsonObject jsonObject = Json.createReader(new StringReader(json)).readObject();
		int value= JsonHelper.getIntValue(jsonObject, "key33", def);
		assertEquals(value, def);
	}

	@Test
	public void testGetBooleanValue() throws Exception {
		String json="{\"key\":true}";
		JsonObject jsonObject = Json.createReader(new StringReader(json)).readObject();
		Boolean value= JsonHelper.getBooleanValue(jsonObject, "key");
		assertNotNull(value);
		assertTrue(value);
		json="{\"key\":false}";
		jsonObject = Json.createReader(new StringReader(json)).readObject();
		value= JsonHelper.getBooleanValue(jsonObject, "key");
		assertNotNull(value);
		assertFalse(value);
		value= JsonHelper.getBooleanValue(jsonObject, "key44");
		assertNull(value);
	}
}