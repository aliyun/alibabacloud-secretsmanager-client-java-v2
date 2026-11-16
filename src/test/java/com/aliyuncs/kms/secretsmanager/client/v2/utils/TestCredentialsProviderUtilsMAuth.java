package com.aliyuncs.kms.secretsmanager.client.v2.utils;

import com.aliyuncs.kms.secretsmanager.client.v2.mauth.config.AuthConfig;
import org.junit.Test;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.*;

public class TestCredentialsProviderUtilsMAuth {

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

    @Test
    public void testInitMAuthConfig_ClientKey_WithEnvPassword() throws IOException {
        File configFile = createTempFile("client_key_config", "{}");
        String envName = "TEST_MAUTH_CLIENT_KEY_PWD";
        String oldValue = System.getenv(envName);
        try {
            Map<String, String> map = new HashMap<String, String>();
            map.put(CacheClientConstant.VARIABLE_CREDENTIALS_TYPE_KEY, CacheClientConstant.VARIABLE_CREDENTIALS_TYPE_CLIENT_KEY);
            map.put(CacheClientConstant.VARIABLE_CLIENT_KEY_CONFIG_PATH_KEY, configFile.getAbsolutePath());
            map.put(CacheClientConstant.VARIABLE_CLIENT_KEY_PASSWORD_ENV_KEY, envName);

            // Java 的 System.getenv 返回的 Map 是不可变的，无法直接设置环境变量。
            // 这里通过直接传入 password 来模拟环境变量已设置的场景
            map.put(CacheClientConstant.VARIABLE_CLIENT_KEY_PASSWORD_KEY, "test_password_from_env");

            AuthConfig config = CredentialsProviderUtils.initMAuthConfig(map, CacheClientConstant.SOURCE_TYPE_CONFIG);
            assertNotNull(config);
            assertEquals(AuthConfig.CLIENT_KEY, config.getAuthMethod());
            assertEquals(configFile.getAbsolutePath(), config.getClientKeyConfigPath());
            assertEquals("test_password_from_env", config.getClientKeyPassword());
        } finally {
            // do nothing
        }
    }

    @Test
    public void testInitMAuthConfig_ClientKey_WithPasswordPath() throws IOException {
        File configFile = createTempFile("client_key_config", "{}");
        File pwdFile = createTempFile("client_key_pwd", "test_password");
        Map<String, String> map = new HashMap<String, String>();
        map.put(CacheClientConstant.VARIABLE_CREDENTIALS_TYPE_KEY, CacheClientConstant.VARIABLE_CREDENTIALS_TYPE_CLIENT_KEY);
        map.put(CacheClientConstant.VARIABLE_CLIENT_KEY_CONFIG_PATH_KEY, configFile.getAbsolutePath());
        map.put(CacheClientConstant.VARIABLE_CLIENT_KEY_PASSWORD_PATH_KEY, pwdFile.getAbsolutePath());

        AuthConfig config = CredentialsProviderUtils.initMAuthConfig(map, CacheClientConstant.SOURCE_TYPE_CONFIG);
        assertNotNull(config);
        assertEquals(pwdFile.getAbsolutePath(), config.getClientKeyPasswordPath());
        assertNull(config.getClientKeyPassword());
    }

    @Test
    public void testInitMAuthConfig_ClientKey_MissingPassword() throws IOException {
        File configFile = createTempFile("client_key_config", "{}");
        Map<String, String> map = new HashMap<String, String>();
        map.put(CacheClientConstant.VARIABLE_CREDENTIALS_TYPE_KEY, CacheClientConstant.VARIABLE_CREDENTIALS_TYPE_CLIENT_KEY);
        map.put(CacheClientConstant.VARIABLE_CLIENT_KEY_CONFIG_PATH_KEY, configFile.getAbsolutePath());

        try {
            CredentialsProviderUtils.initMAuthConfig(map, CacheClientConstant.SOURCE_TYPE_CONFIG);
            fail("Expected IllegalArgumentException");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains(CacheClientConstant.VARIABLE_CLIENT_KEY_PASSWORD_ENV_KEY));
            assertTrue(e.getMessage().contains(CacheClientConstant.VARIABLE_CLIENT_KEY_PASSWORD_PATH_KEY));
        }
    }

    @Test
    public void testInitMAuthConfig_ClientKey_MissingConfigPath() {
        Map<String, String> map = new HashMap<String, String>();
        map.put(CacheClientConstant.VARIABLE_CREDENTIALS_TYPE_KEY, CacheClientConstant.VARIABLE_CREDENTIALS_TYPE_CLIENT_KEY);
        map.put(CacheClientConstant.VARIABLE_CLIENT_KEY_PASSWORD_ENV_KEY, "TEST_PWD");

        try {
            CredentialsProviderUtils.initMAuthConfig(map, CacheClientConstant.SOURCE_TYPE_CONFIG);
            fail("Expected IllegalArgumentException");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains(CacheClientConstant.VARIABLE_CLIENT_KEY_CONFIG_PATH_KEY));
        }
    }

    @Test
    public void testInitMAuthConfig_ClientKey_ConfigFileNotExist() {
        Map<String, String> map = new HashMap<String, String>();
        map.put(CacheClientConstant.VARIABLE_CREDENTIALS_TYPE_KEY, CacheClientConstant.VARIABLE_CREDENTIALS_TYPE_CLIENT_KEY);
        map.put(CacheClientConstant.VARIABLE_CLIENT_KEY_CONFIG_PATH_KEY, "/not/exist/config.json");
        map.put(CacheClientConstant.VARIABLE_CLIENT_KEY_PASSWORD_KEY, "test_password");

        try {
            CredentialsProviderUtils.initMAuthConfig(map, CacheClientConstant.SOURCE_TYPE_CONFIG);
            fail("Expected IllegalArgumentException");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains(CacheClientConstant.VARIABLE_CLIENT_KEY_CONFIG_PATH_KEY));
        }
    }

    @Test
    public void testInitMAuthConfig_ClientKey_PasswordFileNotExist() throws IOException {
        File configFile = createTempFile("client_key_config", "{}");
        Map<String, String> map = new HashMap<String, String>();
        map.put(CacheClientConstant.VARIABLE_CREDENTIALS_TYPE_KEY, CacheClientConstant.VARIABLE_CREDENTIALS_TYPE_CLIENT_KEY);
        map.put(CacheClientConstant.VARIABLE_CLIENT_KEY_CONFIG_PATH_KEY, configFile.getAbsolutePath());
        map.put(CacheClientConstant.VARIABLE_CLIENT_KEY_PASSWORD_PATH_KEY, "/not/exist/password.txt");

        try {
            CredentialsProviderUtils.initMAuthConfig(map, CacheClientConstant.SOURCE_TYPE_CONFIG);
            fail("Expected IllegalArgumentException");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains(CacheClientConstant.VARIABLE_CLIENT_KEY_PASSWORD_PATH_KEY));
        }
    }

    @Test
    public void testInitMAuthConfig_ACKOidcJwt_Success() throws IOException {
        File tokenFile = createTempFile("token", VALID_JWT);
        Map<String, String> map = new HashMap<String, String>();
        map.put(CacheClientConstant.VARIABLE_CREDENTIALS_TYPE_KEY, CacheClientConstant.VARIABLE_CREDENTIALS_TYPE_ACK);
        map.put(CacheClientConstant.VARIABLE_AAP_ARN_KEY, "arn:test:aap");
        map.put(CacheClientConstant.VARIABLE_TOKEN_PATH_KEY, tokenFile.getAbsolutePath());

        AuthConfig config = CredentialsProviderUtils.initMAuthConfig(map, CacheClientConstant.SOURCE_TYPE_CONFIG);
        assertNotNull(config);
        assertEquals(AuthConfig.ACK_OIDC_JWT, config.getAuthMethod());
        assertEquals("arn:test:aap", config.getAapArn());
        assertEquals(tokenFile.getAbsolutePath(), config.getTokenPath());
    }

    @Test
    public void testInitMAuthConfig_ACKOidcJwt_MissingAapArn() throws IOException {
        File tokenFile = createTempFile("token", VALID_JWT);
        Map<String, String> map = new HashMap<String, String>();
        map.put(CacheClientConstant.VARIABLE_CREDENTIALS_TYPE_KEY, CacheClientConstant.VARIABLE_CREDENTIALS_TYPE_ACK);
        map.put(CacheClientConstant.VARIABLE_TOKEN_PATH_KEY, tokenFile.getAbsolutePath());

        try {
            CredentialsProviderUtils.initMAuthConfig(map, CacheClientConstant.SOURCE_TYPE_CONFIG);
            fail("Expected IllegalArgumentException");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains(CacheClientConstant.VARIABLE_AAP_ARN_KEY));
        }
    }

    @Test
    public void testInitMAuthConfig_ACKOidcJwt_MissingTokenPath() {
        Map<String, String> map = new HashMap<String, String>();
        map.put(CacheClientConstant.VARIABLE_CREDENTIALS_TYPE_KEY, CacheClientConstant.VARIABLE_CREDENTIALS_TYPE_ACK);
        map.put(CacheClientConstant.VARIABLE_AAP_ARN_KEY, "arn:test:aap");

        try {
            CredentialsProviderUtils.initMAuthConfig(map, CacheClientConstant.SOURCE_TYPE_CONFIG);
            fail("Expected IllegalArgumentException");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains(CacheClientConstant.VARIABLE_TOKEN_PATH_KEY));
        }
    }

    @Test
    public void testInitMAuthConfig_ECSInstanceIdentity_Success() {
        Map<String, String> map = new HashMap<String, String>();
        map.put(CacheClientConstant.VARIABLE_CREDENTIALS_TYPE_KEY, CacheClientConstant.VARIABLE_CREDENTIALS_TYPE_ECS);
        map.put(CacheClientConstant.VARIABLE_AAP_ARN_KEY, "arn:test:aap");

        AuthConfig config = CredentialsProviderUtils.initMAuthConfig(map, CacheClientConstant.SOURCE_TYPE_CONFIG);
        assertNotNull(config);
        assertEquals(AuthConfig.ECS_INSTANCE_IDENTITY, config.getAuthMethod());
        assertEquals("arn:test:aap", config.getAapArn());
    }

    @Test
    public void testInitMAuthConfig_ECSInstanceIdentity_MissingAapArn() {
        Map<String, String> map = new HashMap<String, String>();
        map.put(CacheClientConstant.VARIABLE_CREDENTIALS_TYPE_KEY, CacheClientConstant.VARIABLE_CREDENTIALS_TYPE_ECS);

        try {
            CredentialsProviderUtils.initMAuthConfig(map, CacheClientConstant.SOURCE_TYPE_CONFIG);
            fail("Expected IllegalArgumentException");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains(CacheClientConstant.VARIABLE_AAP_ARN_KEY));
        }
    }

    @Test
    public void testInitMAuthConfig_EmptyCredentialsType() {
        Map<String, String> map = new HashMap<String, String>();
        AuthConfig config = CredentialsProviderUtils.initMAuthConfig(map, CacheClientConstant.SOURCE_TYPE_CONFIG);
        assertNull(config);
    }

    @Test
    public void testInitMAuthConfig_UnsupportedCredentialsType() {
        Map<String, String> map = new HashMap<String, String>();
        map.put(CacheClientConstant.VARIABLE_CREDENTIALS_TYPE_KEY, "unsupported_type");
        AuthConfig config = CredentialsProviderUtils.initMAuthConfig(map, CacheClientConstant.SOURCE_TYPE_CONFIG);
        assertNull(config);
    }
}
