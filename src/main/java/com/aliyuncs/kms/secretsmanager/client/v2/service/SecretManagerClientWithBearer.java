package com.aliyuncs.kms.secretsmanager.client.v2.service;

import com.aliyun.kms20160120.Client;
import com.aliyun.kms20160120.models.GetSecretValueRequest;
import com.aliyun.kms20160120.models.GetSecretValueResponse;
import com.aliyun.tea.TeaException;
import com.aliyun.tea.utils.StringUtils;
import com.aliyun.teaopenapi.models.Config;
import com.aliyun.teautil.models.ExtendsParameters;
import com.aliyun.teautil.models.RuntimeOptions;
import com.aliyuncs.kms.secretsmanager.client.v2.mauth.AuthToken;
import com.aliyuncs.kms.secretsmanager.client.v2.mauth.MAuth;
import com.aliyuncs.kms.secretsmanager.client.v2.model.RegionInfo;
import com.aliyuncs.kms.secretsmanager.client.v2.utils.CacheClientConstant;
import com.aliyuncs.kms.secretsmanager.client.v2.utils.CommonLogger;
import com.aliyuncs.kms.secretsmanager.client.v2.utils.KmsEndpointUtils;
import com.aliyuncs.kms.secretsmanager.client.v2.utils.PrivateCaUtils;
import com.aliyuncs.kms.secretsmanager.client.v2.utils.SignUtils;

import java.util.Map;

public class SecretManagerClientWithBearer {

    private static final String ERROR_INVALID_ACCESS_KEY_ID_NOT_FOUND = "InvalidAccessKeyId.NotFound";

    private final MAuth mauth;

    public SecretManagerClientWithBearer(MAuth mauth) {
        this.mauth = mauth;
    }

    public GetSecretValueResponse getSecretValue(RegionInfo regionInfo, GetSecretValueRequest req) throws Exception {
        try {
            return doGetSecretValueWithBearer(regionInfo, req);
        } catch (TeaException e) {
            if (ERROR_INVALID_ACCESS_KEY_ID_NOT_FOUND.equals(e.getCode())) {
                CommonLogger.getCommonLogger(CacheClientConstant.MODE_NAME).warnf("encountered {}, clear token and retry",ERROR_INVALID_ACCESS_KEY_ID_NOT_FOUND);
                mauth.clearToken();
                return doGetSecretValueWithBearer(regionInfo, req);
            }
            throw e;
        }
    }

    private GetSecretValueResponse doGetSecretValueWithBearer(RegionInfo regionInfo, GetSecretValueRequest req) throws Exception {
        AuthToken token = mauth.getToken();
        if (token == null) {
            throw new Exception("get token error: token is null");
        }

        Map<String, String> queryParams = SignUtils.extractSignParams(req);
        Map<String, String> headers = SignUtils.buildSignHeaders(token.getTokenKeyId(), SignUtils.ACTION_GET_SECRET_VALUE);
        String signature = SignUtils.sign(queryParams, headers, token.getTokenValue());

        Config config = new Config();
        String endpoint = KmsEndpointUtils.resolveEndpoint(regionInfo);
        config.setEndpoint(endpoint);
        if (!StringUtils.isEmpty(endpoint) && endpoint.endsWith(CacheClientConstant.INSTANCE_GATEWAY_DOMAIN_SUFFIX)) {
            String ca = PrivateCaUtils.resolveCa(regionInfo);
            if (!StringUtils.isEmpty(ca)) {
                config.setCa(ca);
            }
        }
        config.setProtocol(CacheClientConstant.DEFAULT_PROTOCOL);
        config.setBearerToken(signature);
        Client client = new Client(config);
        RuntimeOptions runtimeOptions = new RuntimeOptions();
        runtimeOptions.setExtendsParameters(new ExtendsParameters().setHeaders(headers));
        return client.getSecretValueWithOptions(req, runtimeOptions);
    }

    public void close() {
        mauth.close();
    }
}
