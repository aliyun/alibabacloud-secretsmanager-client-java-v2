package com.aliyuncs.kms.secretsmanager.client.v2.service;

import com.aliyuncs.kms.secretsmanager.client.v2.mauth.MAuth;
import com.aliyuncs.kms.secretsmanager.client.v2.mauth.config.AuthConfig;
import org.junit.Test;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.lang.reflect.Field;
import java.util.Map;
import java.util.Properties;

import static org.junit.Assert.*;

public class TestDefaultSecretManagerClientBuilderMAuth {

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

    private SecretManagerClient buildAndInit(DefaultSecretManagerClientBuilder builder) throws Exception {
        SecretManagerClient client = builder.build();
        client.init();
        return client;
    }

    private Map<String, ?> getBearerClients(SecretManagerClient client) throws Exception {
        Field field = client.getClass().getDeclaredField("bearerClients");
        field.setAccessible(true);
        return (Map<String, ?>) field.get(client);
    }

    private MAuth getMAuthFromBearerClient(Object bearerClient) throws Exception {
        Field field = bearerClient.getClass().getDeclaredField("mauth");
        field.setAccessible(true);
        return (MAuth) field.get(bearerClient);
    }

    @Test
    public void testInitMAuth_Hardcode_ClientKey() throws Exception {
        File configFile = createTempFile("client_key_config", "{}");
        File pwdFile = createTempFile("client_key_pwd", "test_password");

        DefaultSecretManagerClientBuilder builder = new DefaultSecretManagerClientBuilder();
        builder.withClientKey(configFile.getAbsolutePath(), pwdFile.getAbsolutePath());
        builder.addRegion("cn-hangzhou");

        SecretManagerClient client = buildAndInit(builder);
        try {
            Map<String, ?> bearerClients = getBearerClients(client);
            assertNotNull(bearerClients);
            assertEquals(1, bearerClients.size());
            assertTrue(bearerClients.containsKey("cn-hangzhou"));

            MAuth mauth = getMAuthFromBearerClient(bearerClients.get("cn-hangzhou"));
            assertNotNull(mauth);
            Field configField = MAuth.class.getDeclaredField("config");
            configField.setAccessible(true);
            AuthConfig authConfig = (AuthConfig) configField.get(mauth);
            assertEquals(AuthConfig.CLIENT_KEY, authConfig.getAuthMethod());
            assertEquals(configFile.getAbsolutePath(), authConfig.getClientKeyConfigPath());
            assertEquals(pwdFile.getAbsolutePath(), authConfig.getClientKeyPasswordPath());
        } finally {
            client.close();
        }
    }

    @Test
    public void testInitMAuth_Hardcode_ACKOidcJwt() throws Exception {
        File tokenFile = createTempFile("token", VALID_JWT);

        DefaultSecretManagerClientBuilder builder = new DefaultSecretManagerClientBuilder();
        builder.withACKOidcJwt("arn:test:aap", tokenFile.getAbsolutePath());
        builder.addRegion("cn-hangzhou");

        SecretManagerClient client = buildAndInit(builder);
        try {
            Map<String, ?> bearerClients = getBearerClients(client);
            assertNotNull(bearerClients);
            assertEquals(1, bearerClients.size());

            MAuth mauth = getMAuthFromBearerClient(bearerClients.get("cn-hangzhou"));
            assertNotNull(mauth);
            Field configField = MAuth.class.getDeclaredField("config");
            configField.setAccessible(true);
            AuthConfig authConfig = (AuthConfig) configField.get(mauth);
            assertEquals(AuthConfig.ACK_OIDC_JWT, authConfig.getAuthMethod());
            assertEquals("arn:test:aap", authConfig.getAapArn());
            assertEquals(tokenFile.getAbsolutePath(), authConfig.getTokenPath());
        } finally {
            client.close();
        }
    }

    @Test
    public void testInitMAuth_Hardcode_ECSInstanceIdentity() throws Exception {
        DefaultSecretManagerClientBuilder builder = new DefaultSecretManagerClientBuilder();
        builder.withECSInstanceIdentity("arn:test:aap");
        builder.addRegion("cn-hangzhou");

        SecretManagerClient client = buildAndInit(builder);
        try {
            Map<String, ?> bearerClients = getBearerClients(client);
            assertNotNull(bearerClients);
            assertEquals(1, bearerClients.size());

            MAuth mauth = getMAuthFromBearerClient(bearerClients.get("cn-hangzhou"));
            assertNotNull(mauth);
            Field configField = MAuth.class.getDeclaredField("config");
            configField.setAccessible(true);
            AuthConfig authConfig = (AuthConfig) configField.get(mauth);
            assertEquals(AuthConfig.ECS_INSTANCE_IDENTITY, authConfig.getAuthMethod());
            assertEquals("arn:test:aap", authConfig.getAapArn());
        } finally {
            client.close();
        }
    }

    @Test
    public void testInitMAuth_ConfigFile_ClientKey_PasswordPath() throws Exception {
        File configFile = createTempFile("client_key_config", "{}");
        File pwdFile = createTempFile("client_key_pwd", "test_password");
        File propsFile = createTempFile("secretsmanager", ""
                + "credentials_type=client_key\n"
                + "client_key_private_key_path=" + configFile.getAbsolutePath().replace("\\", "/") + "\n"
                + "client_key_password_from_file_path=" + pwdFile.getAbsolutePath().replace("\\", "/") + "\n"
                + "cache_client_region_id=[{\"regionId\":\"cn-hangzhou\"}]\n");

        DefaultSecretManagerClientBuilder builder = new DefaultSecretManagerClientBuilder();
        builder.withCustomConfigFile(propsFile.getAbsolutePath());

        SecretManagerClient client = buildAndInit(builder);
        try {
            Map<String, ?> bearerClients = getBearerClients(client);
            assertNotNull(bearerClients);
            assertFalse(bearerClients.isEmpty());
        } finally {
            client.close();
        }
    }

    @Test
    public void testInitMAuth_ConfigFile_ACKOidcJwt() throws Exception {
        File tokenFile = createTempFile("token", VALID_JWT);
        File propsFile = createTempFile("secretsmanager", ""
                + "credentials_type=ack_oidc_jwt\n"
                + "aap_arn=arn:test:aap\n"
                + "token_path=" + tokenFile.getAbsolutePath().replace("\\", "/") + "\n"
                + "cache_client_region_id=[{\"regionId\":\"cn-hangzhou\"}]\n");

        DefaultSecretManagerClientBuilder builder = new DefaultSecretManagerClientBuilder();
        builder.withCustomConfigFile(propsFile.getAbsolutePath());

        SecretManagerClient client = buildAndInit(builder);
        try {
            Map<String, ?> bearerClients = getBearerClients(client);
            assertNotNull(bearerClients);
            assertFalse(bearerClients.isEmpty());
        } finally {
            client.close();
        }
    }

    @Test
    public void testInitMAuth_ConfigFile_ECSInstanceIdentity() throws Exception {
        File propsFile = createTempFile("secretsmanager", ""
                + "credentials_type=ecs_instance_identity\n"
                + "aap_arn=arn:test:aap\n"
                + "cache_client_region_id=[{\"regionId\":\"cn-hangzhou\"}]\n");

        DefaultSecretManagerClientBuilder builder = new DefaultSecretManagerClientBuilder();
        builder.withCustomConfigFile(propsFile.getAbsolutePath());

        SecretManagerClient client = buildAndInit(builder);
        try {
            Map<String, ?> bearerClients = getBearerClients(client);
            assertNotNull(bearerClients);
            assertFalse(bearerClients.isEmpty());
        } finally {
            client.close();
        }
    }
}
