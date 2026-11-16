package com.aliyuncs.kms.secretsmanager.client.v2.mauth.authenticator;

import org.junit.Test;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

import static org.junit.Assert.*;

public class TestAckOIDCAuthenticator {

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
    public void testGetIdentity_Success() throws Exception {
        File tokenFile = createTempFile("token", VALID_JWT);
        AckOIDCAuthenticator auth = new AckOIDCAuthenticator(tokenFile.getAbsolutePath());
        Identity identity = auth.getIdentity();
        assertNotNull(identity);
        assertEquals(Identity.IDENTITY_TYPE_JWT, identity.getIdentityType());
        assertEquals(VALID_JWT, identity.getIdentityValue());
    }

    @Test
    public void testGetIdentity_InvalidJWT() throws Exception {
        File tokenFile = createTempFile("token", "invalid jwt");
        AckOIDCAuthenticator auth = new AckOIDCAuthenticator(tokenFile.getAbsolutePath());
        try {
            auth.getIdentity();
            fail("Expected IllegalArgumentException");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains("invalid JWT format"));
        }
    }

    @Test
    public void testGetIdentity_FileNotExist() {
        AckOIDCAuthenticator auth = new AckOIDCAuthenticator("/not/exist/token.txt");
        try {
            auth.getIdentity();
            fail("Expected Exception");
        } catch (Exception e) {
            assertTrue(e instanceof IOException || e.getCause() instanceof IOException);
        }
    }
}
