package com.aliyuncs.kms.secretsmanager.client.v2.mauth.utils;

import org.junit.Test;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Date;
import java.util.Map;

import static org.junit.Assert.*;

public class TestJwtUtils {

    private static final String VALID_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0IiwiZXhwIjoxODkzNDU2MDAwfQ.test_signature";
    private static final String JWT_WITHOUT_EXP = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.test_signature";

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
    public void testIsValidJWT_Valid() {
        assertTrue(JwtUtils.isValidJWT(VALID_JWT));
    }

    @Test
    public void testIsValidJWT_Invalid_NotThreeParts() {
        assertFalse(JwtUtils.isValidJWT("invalid.jwt"));
    }

    @Test
    public void testIsValidJWT_Invalid_NotBase64() {
        assertFalse(JwtUtils.isValidJWT("header.payload.signature"));
    }

    @Test
    public void testIsValidJWTFile_ValidFile() throws IOException {
        File file = createTempFile("jwt", VALID_JWT);
        assertTrue(JwtUtils.isValidJWTFile(file.getAbsolutePath()));
    }

    @Test
    public void testIsValidJWTFile_NonExistent() {
        assertFalse(JwtUtils.isValidJWTFile("/not/exist/token.txt"));
    }

    @Test
    public void testIsValidJWTFile_InvalidContent() throws IOException {
        File file = createTempFile("jwt", "invalid jwt content");
        assertFalse(JwtUtils.isValidJWTFile(file.getAbsolutePath()));
    }

    @Test
    public void testParseJWTClaims_Success() throws Exception {
        Map<String, Object> claims = JwtUtils.parseJWTClaims(VALID_JWT);
        assertNotNull(claims);
        assertEquals("test", claims.get("sub"));
    }

    @Test
    public void testParseJWTClaims_InvalidFormat() {
        try {
            JwtUtils.parseJWTClaims("invalid.jwt");
            fail("Expected IllegalArgumentException");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains("invalid JWT format"));
        } catch (Exception e) {
            fail("Expected IllegalArgumentException but got " + e.getClass().getName());
        }
    }

    @Test
    public void testGetJWTExpiration_Success() throws Exception {
        Date exp = JwtUtils.getJWTExpiration(VALID_JWT);
        assertNotNull(exp);
        assertEquals(1893456000000L, exp.getTime());
    }

    @Test
    public void testGetJWTExpiration_MissingExp() {
        try {
            JwtUtils.getJWTExpiration(JWT_WITHOUT_EXP);
            fail("Expected IllegalArgumentException");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().contains("JWT does not contain 'exp' claim"));
        } catch (Exception e) {
            fail("Expected IllegalArgumentException but got " + e.getClass().getName());
        }
    }
}
