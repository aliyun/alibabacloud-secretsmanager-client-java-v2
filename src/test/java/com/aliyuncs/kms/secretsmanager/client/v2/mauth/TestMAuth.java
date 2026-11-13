package com.aliyuncs.kms.secretsmanager.client.v2.mauth;

import com.aliyuncs.kms.secretsmanager.client.v2.mauth.config.AuthConfig;
import org.junit.Test;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Date;

import static org.junit.Assert.*;

public class TestMAuth {

    private static final String VALID_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.test_signature";

    private File createTempFile(String prefix, String content) throws IOException {
        File file = File.createTempFile(prefix, ".tmp");
        file.deleteOnExit();
        if (content != null) {
            FileWriter writer = new FileWriter(file);
            writer.write(content);
            writer.close();
        }
        return file;
    }

    private AuthConfig buildClientKeyConfig(File configFile, String password, File passwordFile) {
        AuthConfig config = new AuthConfig();
        config.setAuthMethod(AuthConfig.CLIENT_KEY);
        config.setKmsEndpoint("kms.cn-hangzhou.aliyuncs.com");
        config.setClientKeyConfigPath(configFile.getAbsolutePath());
        config.setClientKeyPassword(password);
        config.setClientKeyPasswordPath(passwordFile != null ? passwordFile.getAbsolutePath() : null);
        return config;
    }

    private AuthConfig buildAckConfig(File tokenFile) {
        AuthConfig config = new AuthConfig();
        config.setAuthMethod(AuthConfig.ACK_OIDC_JWT);
        config.setKmsEndpoint("kms.cn-hangzhou.aliyuncs.com");
        config.setAapArn("arn:test:aap");
        config.setTokenPath(tokenFile != null ? tokenFile.getAbsolutePath() : null);
        return config;
    }

    private AuthConfig buildEcsConfig() {
        AuthConfig config = new AuthConfig();
        config.setAuthMethod(AuthConfig.ECS_INSTANCE_IDENTITY);
        config.setKmsEndpoint("kms.cn-hangzhou.aliyuncs.com");
        config.setAapArn("arn:test:aap");
        return config;
    }

    @Test
    public void testNewMAuth_ClientKey_Success() throws Exception {
        File configFile = createTempFile("client_key_config", "{}");
        AuthConfig config = buildClientKeyConfig(configFile, "test_password", null);
        MAuth mauth = new MAuth(config);
        assertNotNull(mauth);
        java.lang.reflect.Field configField = MAuth.class.getDeclaredField("config");
        configField.setAccessible(true);
        AuthConfig innerConfig = (AuthConfig) configField.get(mauth);
        assertEquals(AuthConfig.CLIENT_KEY, innerConfig.getAuthMethod());
        mauth.close();
    }

    @Test
    public void testNewMAuth_ACKOidcJwt_Success() throws Exception {
        File tokenFile = createTempFile("token", VALID_JWT);
        AuthConfig config = buildAckConfig(tokenFile);
        MAuth mauth = new MAuth(config);
        assertNotNull(mauth);
        mauth.close();
    }

    @Test
    public void testNewMAuth_ECSInstanceIdentity_Success() throws Exception {
        AuthConfig config = buildEcsConfig();
        MAuth mauth = new MAuth(config);
        assertNotNull(mauth);
        mauth.close();
    }

    @Test
    public void testNewMAuth_InvalidAuthMethod() {
        AuthConfig config = new AuthConfig();
        config.setAuthMethod("InvalidMethod");
        config.setKmsEndpoint("kms.cn-hangzhou.aliyuncs.com");
        try {
            new MAuth(config);
            fail("Expected IllegalArgumentException");
        } catch (Exception e) {
            assertTrue(e instanceof IllegalArgumentException);
            assertTrue(e.getMessage().contains("unsupported authentication method"));
        }
    }

    @Test
    public void testNewMAuth_EmptyAuthMethod() {
        AuthConfig config = new AuthConfig();
        config.setKmsEndpoint("kms.cn-hangzhou.aliyuncs.com");
        try {
            new MAuth(config);
            fail("Expected IllegalArgumentException");
        } catch (Exception e) {
            assertTrue(e instanceof IllegalArgumentException);
            assertTrue(e.getMessage().contains("AuthMethod is required"));
        }
    }

    @Test
    public void testNewMAuth_ClientKey_ConfigFileNotExist() {
        AuthConfig config = new AuthConfig();
        config.setAuthMethod(AuthConfig.CLIENT_KEY);
        config.setKmsEndpoint("kms.cn-hangzhou.aliyuncs.com");
        config.setClientKeyConfigPath("/not/exist/config.json");
        config.setClientKeyPassword("test_password");
        try {
            new MAuth(config);
            fail("Expected IllegalArgumentException");
        } catch (Exception e) {
            assertTrue(e instanceof IllegalArgumentException);
            assertTrue(e.getMessage().contains("client key config file does not exist"));
        }
    }

    @Test
    public void testNewMAuth_ClientKey_MissingPassword() throws IOException {
        File configFile = createTempFile("client_key_config", "{}");
        AuthConfig config = buildClientKeyConfig(configFile, null, null);
        config.setClientKeyPasswordPath(null);
        try {
            new MAuth(config);
            fail("Expected IllegalArgumentException");
        } catch (Exception e) {
            assertTrue(e instanceof IllegalArgumentException);
            assertTrue(e.getMessage().contains("ClientKeyPassword or ClientKeyPasswordPath is required"));
        }
    }

    @Test
    public void testGetToken_CacheHit_ClientKey() throws Exception {
        File configFile = createTempFile("client_key_config", "{}");
        AuthConfig config = buildClientKeyConfig(configFile, "test_password", null);
        MAuth mauth = new MAuth(config);

        // 通过反射设置缓存token
        java.lang.reflect.Field cacheTokenField = MAuth.class.getDeclaredField("cacheToken");
        cacheTokenField.setAccessible(true);
        java.util.Map<String, AuthToken> cache = (java.util.Map<String, AuthToken>) cacheTokenField.get(mauth);
        AuthToken token = new AuthToken();
        token.setTokenType(AuthToken.AUTH_TOKEN_TYPE_CLIENT_KEY);
        token.setTokenKeyId("test-key-id");
        token.setTokenValue("test-token-value");
        token.setExpiresAt(new Date(System.currentTimeMillis() + 72 * 60 * 60 * 1000));
        cache.put(AuthToken.AUTH_TOKEN_TYPE_CLIENT_KEY, token);

        AuthToken result = mauth.getToken();
        assertNotNull(result);
        assertEquals("test-key-id", result.getTokenKeyId());
        assertEquals("test-token-value", result.getTokenValue());
        mauth.close();
    }

    @Test
    public void testClearToken_ClientKey() throws Exception {
        File configFile = createTempFile("client_key_config", "{}");
        AuthConfig config = buildClientKeyConfig(configFile, "test_password", null);
        MAuth mauth = new MAuth(config);

        java.lang.reflect.Field cacheTokenField = MAuth.class.getDeclaredField("cacheToken");
        cacheTokenField.setAccessible(true);
        java.util.Map<String, AuthToken> cache = (java.util.Map<String, AuthToken>) cacheTokenField.get(mauth);
        AuthToken token = new AuthToken();
        token.setTokenType(AuthToken.AUTH_TOKEN_TYPE_CLIENT_KEY);
        token.setTokenKeyId("test-key-id");
        token.setExpiresAt(new Date(System.currentTimeMillis() + 72 * 60 * 60 * 1000));
        cache.put(AuthToken.AUTH_TOKEN_TYPE_CLIENT_KEY, token);

        mauth.clearToken();
        assertTrue(cache.isEmpty());
        mauth.close();
    }

    @Test
    public void testGetToken_ClientKey_InvalidConfigFormat() throws Exception {
        File configFile = createTempFile("client_key_config", "");
        File pwdFile = createTempFile("client_key_pwd", "test_password");
        AuthConfig config = buildClientKeyConfig(configFile, null, pwdFile);
        MAuth mauth = new MAuth(config);
        try {
            mauth.getToken();
            fail("Expected Exception");
        } catch (Exception e) {
            assertTrue(e.getMessage().contains("failed to unmarshal client key config"));
        } finally {
            mauth.close();
        }
    }

    @Test
    public void testGetToken_ClientKey_MissingPassword() throws Exception {
        File configFile = createTempFile("client_key_config", "{\"KeyId\":\"test\",\"PrivateKeyData\":\"test\"}");
        AuthConfig config = buildClientKeyConfig(configFile, null, null);
        // 跳过构造时的validate检查，直接构造
        // 但由于AuthConfig.validate会检查passwordPath，如果都为空则构造失败
        // 所以我们需要构造一个passwordPath存在但password为空的config，然后在运行时清空passwordPath？
        // 或者使用反射直接构造MAuth并设置config
        // 更简单的方式：直接构造一个合法的MAuth，然后反射修改config的password和passwordPath为null
        File pwdFile = createTempFile("client_key_pwd", "test_password");
        config.setClientKeyPasswordPath(pwdFile.getAbsolutePath());
        MAuth mauth = new MAuth(config);

        java.lang.reflect.Field configField = MAuth.class.getDeclaredField("config");
        configField.setAccessible(true);
        AuthConfig innerConfig = (AuthConfig) configField.get(mauth);
        innerConfig.setClientKeyPassword(null);
        innerConfig.setClientKeyPasswordPath(null);

        try {
            mauth.getToken();
            fail("Expected Exception");
        } catch (Exception e) {
            assertTrue(e.getMessage().contains("client key password or password path is not set"));
        } finally {
            mauth.close();
        }
    }
}
