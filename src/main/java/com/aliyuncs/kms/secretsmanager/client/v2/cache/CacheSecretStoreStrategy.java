package com.aliyuncs.kms.secretsmanager.client.v2.cache;

import com.aliyuncs.kms.secretsmanager.client.v2.exception.CacheSecretException;
import com.aliyuncs.kms.secretsmanager.client.v2.model.CacheSecretInfo;

import java.io.Closeable;

/**
 * 缓存secret策略
 */
public interface CacheSecretStoreStrategy extends Closeable {

    /**
     * 初始化凭据缓存
     */
    void init() throws CacheSecretException;

    /**
     * 缓存secret信息
     *
     * @param cacheSecretInfo 指定缓存secret信息
     */
    void storeSecret(final CacheSecretInfo cacheSecretInfo) throws CacheSecretException;

    /**
     * 获取secret缓存信息
     *
     * @param secretName 指定缓存secret名称
     * @return 缓存secret信息
     */
    CacheSecretInfo getCacheSecretInfo(final String secretName) throws CacheSecretException;
}
