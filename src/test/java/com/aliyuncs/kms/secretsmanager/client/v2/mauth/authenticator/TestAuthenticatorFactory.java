package com.aliyuncs.kms.secretsmanager.client.v2.mauth.authenticator;

import org.junit.Test;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

import static org.junit.Assert.*;

public class TestAuthenticatorFactory {

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
    public void testCreate_ECSInstanceIdentity() throws Exception {
        AuthenticatorConfig config = new AuthenticatorConfig();
        config.setAuthMethod(AuthenticatorConfig.ECS_INSTANCE_IDENTITY);
        Authenticator auth = AuthenticatorFactory.create(config);
        assertNotNull(auth);
        assertTrue(auth instanceof ECSAuthenticator);
    }

    @Test
    public void testCreate_ACKOidcJwt_WithTokenPath() throws Exception {
        File tokenFile = createTempFile("token", VALID_JWT);
        AuthenticatorConfig config = new AuthenticatorConfig();
        config.setAuthMethod(AuthenticatorConfig.ACK_OIDC_JWT);
        config.setTokenPath(tokenFile.getAbsolutePath());
        Authenticator auth = AuthenticatorFactory.create(config);
        assertNotNull(auth);
        assertTrue(auth instanceof AckOIDCAuthenticator);
    }

    @Test
    public void testCreate_ACKOidcJwt_WithDefaultTokenPath() throws Exception {
        AuthenticatorConfig config = new AuthenticatorConfig();
        config.setAuthMethod(AuthenticatorConfig.ACK_OIDC_JWT);
        config.setTokenPath(null);
        Authenticator auth = AuthenticatorFactory.create(config);
        assertNotNull(auth);
        assertTrue(auth instanceof AckOIDCAuthenticator);
    }

    @Test
    public void testCreate_EmptyAuthMethod() {
        AuthenticatorConfig config = new AuthenticatorConfig();
        try {
            AuthenticatorFactory.create(config);
            fail("Expected IllegalArgumentException");
        } catch (Exception e) {
            assertTrue(e instanceof IllegalArgumentException);
            assertTrue(e.getMessage().contains("AuthMethod is required"));
        }
    }

    @Test
    public void testCreate_InvalidAuthMethod() {
        AuthenticatorConfig config = new AuthenticatorConfig();
        config.setAuthMethod("InvalidMethod");
        try {
            AuthenticatorFactory.create(config);
            fail("Expected IllegalArgumentException");
        } catch (Exception e) {
            assertTrue(e instanceof IllegalArgumentException);
            assertTrue(e.getMessage().contains("unsupported authentication method"));
        }
    }
}
