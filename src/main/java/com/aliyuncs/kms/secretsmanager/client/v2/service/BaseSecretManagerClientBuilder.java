package com.aliyuncs.kms.secretsmanager.client.v2.service;

import com.aliyuncs.kms.secretsmanager.client.v2.CacheClientBuilder;

public abstract class BaseSecretManagerClientBuilder implements CacheClientBuilder<SecretManagerClient> {
    /**
     * 构建默认凭据管家ClientBuilder
     *
     * @return 默认凭据管家ClientBuilder
     */
    public static DefaultSecretManagerClientBuilder standard() {
        return new DefaultSecretManagerClientBuilder();
    }

}
