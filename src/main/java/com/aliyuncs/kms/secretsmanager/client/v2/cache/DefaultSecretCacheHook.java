package com.aliyuncs.kms.secretsmanager.client.v2.cache;

import com.aliyun.tea.TeaException;
import com.aliyuncs.kms.secretsmanager.client.v2.exception.CacheSecretException;
import com.aliyuncs.kms.secretsmanager.client.v2.model.CacheSecretInfo;
import com.aliyuncs.kms.secretsmanager.client.v2.model.SecretInfo;

import java.io.IOException;

/**
 * 默认hook,不做特殊操作
 */
public class DefaultSecretCacheHook implements SecretCacheHook {
    /**
     * 缓存的凭据Version Stage
     */
    private final String stage;

    public DefaultSecretCacheHook(final String stage) {
        this.stage = stage;
    }

    @Override
    public void init() throws CacheSecretException {
        // do nothing
    }

    @Override
    public CacheSecretInfo put(final SecretInfo secretInfo) {
        return new CacheSecretInfo(secretInfo, stage, System.currentTimeMillis());
    }

    @Override
    public SecretInfo get(final CacheSecretInfo cacheSecretInfo) {
        return cacheSecretInfo.getSecretInfo();
    }

    @Override
    public SecretInfo recoveryGetSecret(final String secretName) throws TeaException {
        return null;
    }

    @Override
    public void close() throws IOException {
        // do nothing
    }
}
