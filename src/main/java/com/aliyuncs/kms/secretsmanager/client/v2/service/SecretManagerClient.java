package com.aliyuncs.kms.secretsmanager.client.v2.service;

import com.aliyun.kms20160120.models.GetSecretValueRequest;
import com.aliyun.kms20160120.models.GetSecretValueResponse;
import com.aliyuncs.kms.secretsmanager.client.v2.exception.CacheSecretException;

import java.io.Closeable;

public interface SecretManagerClient extends Closeable {

    /**
     * 初始化Client
     *
     * @throws CacheSecretException
     */
    void init() throws CacheSecretException;

    /**
     * 获取指定凭据信息
     *
     * @param req 获取指定凭据请求
     * @return 指定凭据信息
     */
    GetSecretValueResponse getSecretValue(GetSecretValueRequest req) throws Exception;
}
