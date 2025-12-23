package com.aliyuncs.kms.secretsmanager.client.v2;

import com.aliyuncs.kms.secretsmanager.client.v2.cache.FileCacheSecretStoreStrategy;
import com.aliyuncs.kms.secretsmanager.client.v2.exception.CacheSecretException;
import com.aliyuncs.kms.secretsmanager.client.v2.model.SecretInfo;
import com.aliyuncs.kms.secretsmanager.client.v2.service.BaseSecretManagerClientBuilder;
import com.aliyuncs.kms.secretsmanager.client.v2.service.DefaultRefreshSecretStrategy;
import com.aliyuncs.kms.secretsmanager.client.v2.service.FullJitterBackoffStrategy;
import com.aliyuncs.kms.secretsmanager.client.v2.utils.CredentialsProviderUtils;
import com.google.gson.Gson;
import org.junit.Test;

public class TestCacheSecret {

    @Test
    public void testGetSecretByEnvOrConf() {
        try {
            SecretCacheClient client = SecretCacheClientBuilder.newClient();
            SecretInfo secretInfo = client.getSecretInfo("#secretName#");
            System.out.println("secretInfo:" + new Gson().toJson(secretInfo));
        } catch (CacheSecretException e) {
            System.out.println("CacheSecretException:" + e.getMessage());
        }
    }

    @Test
    public void testGetSecretByAk() {
        try {
            SecretCacheClient client = SecretCacheClientBuilder.newCacheClientBuilder(
                    BaseSecretManagerClientBuilder.standard().withCredentialsProvider(CredentialsProviderUtils
                            .withAccessKey(System.getenv("#accessKeyId#"), System.getenv("#accessKeySecret#"))).withRegion("#regionId#").build()).build();
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
        try {
            SecretCacheClient client = SecretCacheClientBuilder.newCacheClientBuilder(
                    BaseSecretManagerClientBuilder.standard().withCustomConfigFile("#customConfigFileName#").build()).build();
            SecretInfo secretInfo = client.getSecretInfo("#secretName#");
            System.out.println("secretInfo:" + new Gson().toJson(secretInfo));
        } catch (CacheSecretException e) {
            System.out.println("CacheSecretException:" + e.getMessage());
        }
    }
}
