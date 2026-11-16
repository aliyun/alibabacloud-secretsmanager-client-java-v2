package com.aliyuncs.kms.secretsmanager.client.v2.mauth.config;

import org.junit.Test;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

import static org.junit.Assert.*;

public class TestAuthConfig {

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

    private AuthConfig buildValidClientKeyConfig(File configFile, String password, File passwordFile) {
        AuthConfig config = new AuthConfig();
        config.setAuthMethod(AuthConfig.CLIENT_KEY);
        config.setKmsEndpoint("kms.cn-hangzhou.aliyuncs.com");
        config.setClientKeyConfigPath(configFile.getAbsolutePath());
        config.setClientKeyPassword(password);
        config.setClientKeyPasswordPath(passwordFile != null ? passwordFile.getAbsolutePath() : null);
        return config;
    }

    @Test
    public void testValidate_ClientKey_WithPassword() throws IOException {
        File configFile = createTempFile("client_key_config", "{}");
        AuthConfig config = buildValidClientKeyConfig(configFile, "test_password", null);
        config.validate();
    }

    @Test
    public void testValidate_ClientKey_WithPasswordPath() throws IOException {
        File configFile = createTempFile("client_key_config", "{}");
        File pwdFile = createTempFile("client_key_pwd", "test_password");
        AuthConfig config = buildValidClientKeyConfig(configFile, null, pwdFile);
        config.validate();
    }

    @Test
    public void testValidate_ClientKey_MissingPassword() throws IOException {
        File configFile = createTempFile("client_key_config", "{}");
        AuthConfig config = buildValidClientKeyConfig(configFile, null, null);
        config.setClientKeyPasswordPath(null);
        try {
            config.validate();
            fail("Expected IllegalArgumentException");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains("ClientKeyPassword or ClientKeyPasswordPath is required"));
        }
    }

    @Test
    public void testValidate_ClientKey_ConfigFileNotExist() {
        AuthConfig config = new AuthConfig();
        config.setAuthMethod(AuthConfig.CLIENT_KEY);
        config.setKmsEndpoint("kms.cn-hangzhou.aliyuncs.com");
        config.setClientKeyConfigPath("/not/exist/config.json");
        config.setClientKeyPassword("test_password");
        try {
            config.validate();
            fail("Expected IllegalArgumentException");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains("client key config file does not exist"));
        }
    }

    @Test
    public void testValidate_ClientKey_PasswordFileNotExist() throws IOException {
        File configFile = createTempFile("client_key_config", "{}");
        AuthConfig config = buildValidClientKeyConfig(configFile, null, null);
        config.setClientKeyPasswordPath("/not/exist/password.txt");
        try {
            config.validate();
            fail("Expected IllegalArgumentException");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains("client key password file does not exist"));
        }
    }

    @Test
    public void testValidate_ACKOidcJwt_Success() {
        AuthConfig config = new AuthConfig();
        config.setAuthMethod(AuthConfig.ACK_OIDC_JWT);
        config.setAapArn("test-aap-arn");
        config.setKmsEndpoint("kms.cn-hangzhou.aliyuncs.com");
        config.validate();
    }

    @Test
    public void testValidate_ACKOidcJwt_MissingAapArn() {
        AuthConfig config = new AuthConfig();
        config.setAuthMethod(AuthConfig.ACK_OIDC_JWT);
        config.setKmsEndpoint("kms.cn-hangzhou.aliyuncs.com");
        try {
            config.validate();
            fail("Expected IllegalArgumentException");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains("AapArn is required"));
        }
    }

    @Test
    public void testValidate_ECSInstanceIdentity_Success() {
        AuthConfig config = new AuthConfig();
        config.setAuthMethod(AuthConfig.ECS_INSTANCE_IDENTITY);
        config.setAapArn("test-aap-arn");
        config.setKmsEndpoint("kms.cn-hangzhou.aliyuncs.com");
        config.validate();
    }

    @Test
    public void testValidate_ECSInstanceIdentity_MissingAapArn() {
        AuthConfig config = new AuthConfig();
        config.setAuthMethod(AuthConfig.ECS_INSTANCE_IDENTITY);
        config.setKmsEndpoint("kms.cn-hangzhou.aliyuncs.com");
        try {
            config.validate();
            fail("Expected IllegalArgumentException");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains("AapArn is required"));
        }
    }

    @Test
    public void testValidate_EmptyAuthMethod() {
        AuthConfig config = new AuthConfig();
        config.setKmsEndpoint("kms.cn-hangzhou.aliyuncs.com");
        try {
            config.validate();
            fail("Expected IllegalArgumentException");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains("AuthMethod is required"));
        }
    }

    @Test
    public void testValidate_MissingKmsEndpoint() {
        AuthConfig config = new AuthConfig();
        config.setAuthMethod(AuthConfig.ECS_INSTANCE_IDENTITY);
        try {
            config.validate();
            fail("Expected IllegalArgumentException");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains("KmsEndpoint is required"));
        }
    }

    @Test
    public void testValidate_InvalidAuthMethod() {
        AuthConfig config = new AuthConfig();
        config.setAuthMethod("InvalidMethod");
        config.setKmsEndpoint("kms.cn-hangzhou.aliyuncs.com");
        try {
            config.validate();
            fail("Expected IllegalArgumentException");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains("unsupported authentication method"));
        }
    }
}
