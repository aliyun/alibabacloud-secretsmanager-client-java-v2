package com.aliyuncs.kms.secretsmanager.client.v2.mauth.utils;

import com.aliyuncs.kms.secretsmanager.client.v2.utils.ConfigUtils;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.Base64;

import static org.junit.Assert.*;

public class TestClientKeyUtils {

    private static File tempDir;
    private static String clientKeyConfigPath;
    private static String clientKeyPasswordPath;

    @BeforeClass
    public static void setUp() throws Exception {
        tempDir = Files.createTempDirectory("testClientKey").toFile();
        String password = "test_password";
        byte[] pkcs12Bytes = generatePkcs12(password);
        String privateKeyData = Base64.getEncoder().encodeToString(pkcs12Bytes);

        File passwordFile = new File(tempDir, "password.txt");
        Files.write(passwordFile.toPath(), password.getBytes());
        clientKeyPasswordPath = passwordFile.getAbsolutePath();

        File jsonFile = new File(tempDir, "clientKey.json");
        String json = "{\"KeyId\":\"test-key\",\"PrivateKeyData\":\"" + privateKeyData + "\"}";
        Files.write(jsonFile.toPath(), json.getBytes());
        clientKeyConfigPath = jsonFile.getAbsolutePath();
    }

    @AfterClass
    public static void tearDown() {
        if (tempDir != null) {
            File[] files = tempDir.listFiles();
            if (files != null) {
                for (File f : files) {
                    f.delete();
                }
            }
            tempDir.delete();
        }
    }

    private static byte[] generatePkcs12(String password) throws Exception {
        File p12File = new File(tempDir, "test.p12");
        String keytoolPath = getKeytoolPath();
        ProcessBuilder pb = new ProcessBuilder(
                keytoolPath, "-genkeypair",
                "-alias", "test-alias",
                "-keyalg", "RSA",
                "-keysize", "2048",
                "-validity", "365",
                "-keystore", p12File.getAbsolutePath(),
                "-storetype", "PKCS12",
                "-storepass", password,
                "-keypass", password,
                "-dname", "CN=Test"
        );
        pb.redirectErrorStream(true);
        Process process = pb.start();
        int exitCode = process.waitFor();
        if (exitCode != 0) {
            throw new RuntimeException("keytool failed with exit code " + exitCode);
        }
        return java.nio.file.Files.readAllBytes(p12File.toPath());
    }

    private static String getKeytoolPath() {
        File javaHome = new File(System.getProperty("java.home"));
        String keytoolName = System.getProperty("os.name").toLowerCase().contains("win") ? "keytool.exe" : "keytool";
        File keytool = new File(javaHome, "bin/" + keytoolName);
        if (keytool.exists()) {
            return keytool.getAbsolutePath();
        }
        if (javaHome.getName().equalsIgnoreCase("jre")) {
            keytool = new File(javaHome.getParentFile(), "bin/" + keytoolName);
            if (keytool.exists()) {
                return keytool.getAbsolutePath();
            }
        }
        return "keytool";
    }

    @Test
    public void testExtractClientKey_Success() throws Exception {
        String password = ConfigUtils.readFileContent(clientKeyPasswordPath).trim();
        String configJson = ConfigUtils.readFileContent(clientKeyConfigPath);
        com.google.gson.Gson gson = new com.google.gson.Gson();
        ClientKeyConfig config = gson.fromJson(configJson, ClientKeyConfig.class);
        assertNotNull(config);
        assertNotNull(config.getPrivateKeyData());

        ClientKeyUtils.ClientKeyResult result = ClientKeyUtils.extractClientKey(password, config.getPrivateKeyData());
        assertNotNull(result);
        assertNotNull(result.getPrivateKeyPem());
        assertTrue(result.getPrivateKeyPem().contains("BEGIN"));
        assertTrue(result.getPrivateKeyPem().contains("PRIVATE KEY"));
        assertNotNull(result.getExpiresAt());
    }

    @Test
    public void testExtractClientKey_WrongPassword() throws Exception {
        String configJson = ConfigUtils.readFileContent(clientKeyConfigPath);
        com.google.gson.Gson gson = new com.google.gson.Gson();
        ClientKeyConfig config = gson.fromJson(configJson, ClientKeyConfig.class);
        try {
            ClientKeyUtils.extractClientKey("wrong_password", config.getPrivateKeyData());
            fail("Expected Exception");
        } catch (Exception e) {
            assertTrue(e.getMessage().contains("keystore") || e.getMessage().contains(" tampered") || e.getMessage().contains("password"));
        }
    }

    @Test
    public void testExtractClientKey_InvalidPrivateKeyData() {
        try {
            ClientKeyUtils.extractClientKey("test", "invalid_base64");
            fail("Expected Exception");
        } catch (Exception e) {
            assertTrue(e instanceof IllegalArgumentException || e instanceof java.lang.IllegalArgumentException);
        }
    }

    private static class ClientKeyConfig {
        private String KeyId;
        private String PrivateKeyData;

        public String getKeyId() {
            return KeyId;
        }

        public String getPrivateKeyData() {
            return PrivateKeyData;
        }
    }
}
