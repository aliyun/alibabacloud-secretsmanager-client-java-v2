package com.aliyuncs.kms.secretsmanager.client.v2.mauth.authenticator;

import com.aliyun.tea.Tea;
import com.aliyun.tea.TeaRequest;
import com.aliyun.tea.TeaResponse;
import com.google.gson.Gson;

import java.util.HashMap;
import java.util.Map;

public class ECSAuthenticator implements Authenticator {

    private static final Gson GSON = new Gson();

    @Override
    public Identity getIdentity() throws Exception {
        String token = getMetadataToken();
        String audience = String.valueOf(System.currentTimeMillis() / 1000);

        TeaRequest request = new TeaRequest();
        request.protocol = "http";
        request.method = "GET";
        request.pathname = "/latest/dynamic/instance-identity/pkcs7";
        request.query = new HashMap<>();
        request.query.put("audience", audience);
        request.headers = new HashMap<>();
        request.headers.put("host", "100.100.100.200");
        request.headers.put("X-aliyun-ecs-metadata-token", token);

        Map<String, Object> runtime = new HashMap<>();
        runtime.put("connectTimeout", 2000);
        runtime.put("readTimeout", 2000);

        TeaResponse response = Tea.doAction(request, runtime);
        if (response.statusCode != 200) {
            throw new RuntimeException("failed to get metadata pkcs7: " + response.statusMessage);
        }
        String document = response.getResponseBody().trim();
        Map<String, String> docMap = new HashMap<>();
        docMap.put("Document", document);
        String docJson = GSON.toJson(docMap);
        Identity identity = new Identity();
        identity.setIdentityType(Identity.IDENTITY_TYPE_PKCS7);
        identity.setIdentityValue(docJson);
        return identity;
    }

    private String getMetadataToken() throws Exception {
        TeaRequest request = new TeaRequest();
        request.protocol = "http";
        request.method = "PUT";
        request.pathname = "/latest/api/token";
        request.headers = new HashMap<>();
        request.headers.put("host", "100.100.100.200");
        request.headers.put("X-aliyun-ecs-metadata-token-ttl-seconds", "3600");

        Map<String, Object> runtime = new HashMap<>();
        runtime.put("connectTimeout", 2000);
        runtime.put("readTimeout", 2000);

        TeaResponse response = Tea.doAction(request, runtime);
        if (response.statusCode != 200) {
            throw new RuntimeException("failed to get metadata token: " + response.statusMessage);
        }
        return response.getResponseBody().trim();
    }
}