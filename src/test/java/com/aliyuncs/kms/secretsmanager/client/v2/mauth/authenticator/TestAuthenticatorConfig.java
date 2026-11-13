package com.aliyuncs.kms.secretsmanager.client.v2.mauth.authenticator;

import org.junit.Test;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

import static org.junit.Assert.*;

public class TestAuthenticatorConfig {

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
    public void testValidateConfig_ECSInstanceIdentity_Success() {
        AuthenticatorConfig config = new AuthenticatorConfig();
        config.setAuthMethod(AuthenticatorConfig.ECS_INSTANCE_IDENTITY);
        config.validateConfig();
    }

    @Test
    public void testValidateConfig_ACKOidcJwt_WithValidTokenFile() throws IOException {
        File tokenFile = createTempFile("token", VALID_JWT);
        AuthenticatorConfig config = new AuthenticatorConfig();
        config.setAuthMethod(AuthenticatorConfig.ACK_OIDC_JWT);
        config.setTokenPath(tokenFile.getAbsolutePath());
        config.validateConfig();
    }

    @Test
    public void testValidateConfig_ACKOidcJwt_WithEmptyTokenPath() {
        AuthenticatorConfig config = new AuthenticatorConfig();
        config.setAuthMethod(AuthenticatorConfig.ACK_OIDC_JWT);
        config.setTokenPath("");
        config.validateConfig();
    }

    @Test
    public void testValidateConfig_ACKOidcJwt_WithNullTokenPath() {
        AuthenticatorConfig config = new AuthenticatorConfig();
        config.setAuthMethod(AuthenticatorConfig.ACK_OIDC_JWT);
        config.setTokenPath(null);
        config.validateConfig();
    }

    @Test
    public void testValidateConfig_ACKOidcJwt_InvalidTokenFile() throws IOException {
        File tokenFile = createTempFile("token", "invalid jwt");
        AuthenticatorConfig config = new AuthenticatorConfig();
        config.setAuthMethod(AuthenticatorConfig.ACK_OIDC_JWT);
        config.setTokenPath(tokenFile.getAbsolutePath());
        try {
            config.validateConfig();
            fail("Expected IllegalArgumentException");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains("token file does not exist or has invalid JWT format"));
        }
    }

    @Test
    public void testValidateConfig_EmptyAuthMethod() {
        AuthenticatorConfig config = new AuthenticatorConfig();
        try {
            config.validateConfig();
            fail("Expected IllegalArgumentException");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains("AuthMethod is required"));
        }
    }

    @Test
    public void testValidateConfig_InvalidAuthMethod() {
        AuthenticatorConfig config = new AuthenticatorConfig();
        config.setAuthMethod("InvalidMethod");
        try {
            config.validateConfig();
            fail("Expected IllegalArgumentException");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains("unsupported authentication method"));
        }
    }
}
