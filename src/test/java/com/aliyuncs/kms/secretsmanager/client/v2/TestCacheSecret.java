package com.aliyuncs.kms.secretsmanager.client.v2;

import com.aliyuncs.kms.secretsmanager.client.v2.cache.FileCacheSecretStoreStrategy;
import com.aliyuncs.kms.secretsmanager.client.v2.exception.CacheSecretException;
import com.aliyuncs.kms.secretsmanager.client.v2.model.SecretInfo;
import com.aliyuncs.kms.secretsmanager.client.v2.service.BaseSecretManagerClientBuilder;
import com.aliyuncs.kms.secretsmanager.client.v2.service.DefaultRefreshSecretStrategy;
import com.aliyuncs.kms.secretsmanager.client.v2.service.FullJitterBackoffStrategy;
import com.aliyuncs.kms.secretsmanager.client.v2.utils.CredentialsProviderUtils;
import com.google.gson.Gson;
import org.junit.Assume;
import org.junit.Ignore;
import org.junit.Test;

import java.io.File;
import java.io.IOException;

@Ignore("integration tests: requires real credentials and configuration")
public class TestCacheSecret {

    @Test
    public void testGetSecretByEnvOrConf() {
        Assume.assumeTrue("requires cache_client_region_id or secretsmanager.properties", hasRegionConfig());
        try {
            SecretCacheClient client = SecretCacheClientBuilder.newClient();
            SecretInfo secretInfo = client.getSecretInfo("#secretName#");
            System.out.println("secretInfo:" + new Gson().toJson(secretInfo));
        } catch (CacheSecretException e) {
            System.out.println("CacheSecretException:" + e.getMessage());
        }
    }
    @Test
    public void testGetSecretByHardCode() {
        String clientKeyPrivateKeyPath = "#clientKeyPrivateKeyPath#";
        String clientKeyPasswordFilePath = "#clientKeyPasswordFilePath#";
        String regionId = "#regionId#";
        String secretName = "#secretName#";

        Assume.assumeFalse("client key placeholders not replaced", clientKeyPrivateKeyPath.contains("#"));
        Assume.assumeFalse("client key placeholders not replaced", clientKeyPasswordFilePath.contains("#"));
        Assume.assumeTrue("client key file not found", new File(clientKeyPrivateKeyPath).exists());
        Assume.assumeTrue("client key password file not found", new File(clientKeyPasswordFilePath).exists());

        try (SecretCacheClient client = SecretCacheClientBuilder.newCacheClientBuilder(
                BaseSecretManagerClientBuilder.standard()
                        .withClientKey(clientKeyPrivateKeyPath, clientKeyPasswordFilePath)
                        .withRegion(regionId).build()).build()) {
            SecretInfo secretInfo = client.getSecretInfo(secretName);
            System.out.println("secretValue:" + secretInfo.getSecretValue());
        } catch (CacheSecretException | IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    public void testGetSecretByAk() {
        String accessKeyId = System.getenv("#accessKeyId#");
        String accessKeySecret = System.getenv("#accessKeySecret#");
        String regionId = "#regionId#";
        Assume.assumeTrue("requires accessKeyId/accessKeySecret environment variables", accessKeyId != null && accessKeySecret != null);
        Assume.assumeFalse("region placeholder not replaced", regionId.contains("#"));
        try {
            SecretCacheClient client = SecretCacheClientBuilder.newCacheClientBuilder(
                    BaseSecretManagerClientBuilder.standard().withCredentialsProvider(CredentialsProviderUtils
                            .withAccessKey(accessKeyId, accessKeySecret)).withRegion(regionId).build()).build();
            SecretInfo secretInfo = client.getSecretInfo("#secretName#");
            System.out.println("secretInfo:" + new Gson().toJson(secretInfo));
        } catch (CacheSecretException e) {
            System.out.println("CacheSecretException:" + e.getMessage());
        }
    }

    @Test
    public void testGetSecretByCustom() {
        try {
            SecretCacheClient client = SecretCacheClientBuilder.newCacheClientBuilder(BaseSecretManagerClientBuilder.standard()
                    .withCredentialsProvider(CredentialsProviderUtils.withAccessKey(System.getenv("#accessKeyId#"), System.getenv("#accessKeySecret#")))
                    .withRegion("#regionId#").withBackoffStrategy(new FullJitterBackoffStrategy(3, 2000, 10000)).build())
                    .withCacheSecretStrategy(new FileCacheSecretStoreStrategy("#cacheSecretPath#", true, "#salt#"))
                    .withRefreshSecretStrategy(new DefaultRefreshSecretStrategy("#ttlName#"))
                    .withCacheStage("#stage#").withSecretTTL("#secretName#", 1 * 60 * 1000l).withSecretTTL("#secretName1#", 2 * 60 * 1000l).build();
            SecretInfo secretInfo = client.getSecretInfo("#secretName#");
            System.out.println("secretInfo:" + new Gson().toJson(secretInfo));
        } catch (Exception e) {
            System.out.println("CacheSecretException:" + e.getMessage());
        }
    }

    @Test
    public void testGetSecretByWithCustomConfigFile() {
        String customConfigFileName = "#customConfigFileName#";
        Assume.assumeFalse("config file placeholder not replaced", customConfigFileName.contains("#"));
        Assume.assumeTrue("config file not found", new File(customConfigFileName).exists());
        try {
            SecretCacheClient client = SecretCacheClientBuilder.newCacheClientBuilder(
                    BaseSecretManagerClientBuilder.standard().withCustomConfigFile(customConfigFileName).build()).build();
            SecretInfo secretInfo = client.getSecretInfo("#secretName#");
            System.out.println("secretInfo:" + new Gson().toJson(secretInfo));
        } catch (CacheSecretException e) {
            System.out.println("CacheSecretException:" + e.getMessage());
        }
    }

    private static boolean hasRegionConfig() {
        String regionId = System.getenv("cache_client_region_id");
        if (regionId != null && !regionId.trim().isEmpty()) {
            return true;
        }
        return new File("secretsmanager.properties").exists()
                || TestCacheSecret.class.getClassLoader().getResource("secretsmanager.properties") != null;
    }
}
