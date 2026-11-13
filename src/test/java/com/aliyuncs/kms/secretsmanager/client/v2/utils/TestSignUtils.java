package com.aliyuncs.kms.secretsmanager.client.v2.utils;

import com.aliyun.tea.TeaModel;
import org.junit.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.*;

public class TestSignUtils {

    public static class TestRequest {
        public String secretName;
        public String versionStage;
        public String emptyField;
    }

    public static class TestTeaModel extends TeaModel {
        public String name;
        public String value;
        public String emptyField;
    }

    @Test
    public void testExtractSignParams_WithPlainObject() {
        TestRequest req = new TestRequest();
        req.secretName = "test-secret";
        req.versionStage = "ACSCurrent";
        req.emptyField = "";
        Map<String, String> params = SignUtils.extractSignParams(req);
        assertEquals("test-secret", params.get("secretName"));
        assertEquals("ACSCurrent", params.get("versionStage"));
        assertFalse(params.containsKey("emptyField"));
    }

    @Test
    public void testExtractSignParams_WithTeaModel() {
        TestTeaModel model = new TestTeaModel();
        model.name = "test-name";
        model.value = "test-value";
        model.emptyField = null;
        Map<String, String> params = SignUtils.extractSignParams(model);
        assertEquals("test-name", params.get("name"));
        assertEquals("test-value", params.get("value"));
        assertFalse(params.containsKey("emptyField"));
    }

    @Test
    public void testExtractSignParams_WithNull() {
        Map<String, String> params = SignUtils.extractSignParams(null);
        assertNotNull(params);
        assertTrue(params.isEmpty());
    }

    @Test
    public void testBuildSignHeaders() {
        Map<String, String> headers = SignUtils.buildSignHeaders("test-key-id", SignUtils.ACTION_GET_SECRET_VALUE);
        assertNotNull(headers);
        assertEquals("test-key-id", headers.get(SignUtils.HEADER_ACCESS_KEY_ID));
        assertEquals(SignUtils.ALGO_RSA_PKCS1_SHA256, headers.get(SignUtils.HEADER_SIGNATURE_METHOD));
        assertEquals(SignUtils.ACTION_GET_SECRET_VALUE, headers.get(SignUtils.HEADER_API_NAME));
        assertEquals(SignUtils.API_VERSION_20160102, headers.get(SignUtils.HEADER_API_VERSION));
        assertNotNull(headers.get(SignUtils.HEADER_DATE));
        assertTrue(headers.get(SignUtils.HEADER_DATE).startsWith("20"));
    }

    @Test
    public void testSign_WithValidPrivateKey() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        String base64Key = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
        String privateKeyPem = "-----BEGIN PRIVATE KEY-----\n" + base64Key + "\n-----END PRIVATE KEY-----";

        Map<String, String> queryParams = new HashMap<String, String>();
        queryParams.put("SecretName", "test-secret");
        Map<String, String> headers = SignUtils.buildSignHeaders("key-id", SignUtils.ACTION_GET_SECRET_VALUE);

        String signature = SignUtils.sign(queryParams, headers, privateKeyPem);
        assertNotNull(signature);
        assertFalse(signature.isEmpty());
    }

    @Test
    public void testSign_WithNullParams() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        String base64Key = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
        String privateKeyPem = "-----BEGIN PRIVATE KEY-----\n" + base64Key + "\n-----END PRIVATE KEY-----";

        Map<String, String> headers = SignUtils.buildSignHeaders("key-id", SignUtils.ACTION_GET_SECRET_VALUE);
        String signature = SignUtils.sign(null, headers, privateKeyPem);
        assertNotNull(signature);
        assertFalse(signature.isEmpty());
    }
}
