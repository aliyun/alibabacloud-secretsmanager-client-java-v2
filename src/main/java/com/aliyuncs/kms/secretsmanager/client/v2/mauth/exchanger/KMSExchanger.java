package com.aliyuncs.kms.secretsmanager.client.v2.mauth.exchanger;

import com.aliyun.teaopenapi.Client;
import com.aliyun.teaopenapi.models.Config;
import com.aliyun.teaopenapi.models.OpenApiRequest;
import com.aliyun.teaopenapi.models.Params;
import com.aliyun.teautil.models.RuntimeOptions;
import com.google.gson.Gson;

import java.util.HashMap;
import java.util.Map;

public class KMSExchanger implements Exchanger {

    private static final String ACTION_ISSUE_TEMPORARY_CREDENTIAL = "IssueTemporaryCredential";
    private static final String ARG_AAP_ARN = "AapArn";
    private static final String VERSION = "2016-01-20";

    private final String kmsEndpoint;
    private final String aapArn;
    private final String ca;

    public KMSExchanger(String kmsEndpoint, String aapArn, String ca) {
        this.kmsEndpoint = kmsEndpoint;
        this.aapArn = aapArn;
        this.ca = ca;
    }

    @Override
    public ExchangeResult exchangeCredential(String identity) throws Exception {
        Config config = new Config();
        config.setEndpoint(kmsEndpoint);
        config.setProtocol("https");
        if (ca != null && !ca.isEmpty()) {
            config.setCa(ca);
        }
        config.setBearerToken(identity);
        Map<String, ?> response = issueTemporaryCredential(config);
        Integer statusCode = (Integer) response.get("statusCode");
        if (statusCode == null || statusCode != 200) {
            throw new RuntimeException("failed to call api: " + statusCode);
        }

        @SuppressWarnings("unchecked")
        Map<String, Object> body = (Map<String, Object>) response.get("body");
        TemporaryCredential credential = new Gson().fromJson(new Gson().toJsonTree(body), TemporaryCredential.class);
        ExchangeResult result = new ExchangeResult();
        if (credential != null) {
            result.setTokenType(credential.getCredentialType());
            result.setTokenValue(credential.getCredential());
        }
        return result;
    }

    private Map<String, ?> issueTemporaryCredential(Config config) throws Exception {
        Client client = new Client(config);

        Params params = new Params();
        params.setAction(ACTION_ISSUE_TEMPORARY_CREDENTIAL);
        params.setVersion(VERSION);
        params.setProtocol("HTTPS");
        params.setMethod("POST");
        params.setPathname("/");
        params.setAuthType("bearer");
        params.setStyle("RPC");
        params.setBodyType("json");
        params.setReqBodyType("json");

        Map<String, String> query = new HashMap<>();
        query.put(ARG_AAP_ARN, aapArn);


        OpenApiRequest request = new OpenApiRequest();
        request.setQuery(query);
        RuntimeOptions runtime = new RuntimeOptions();
        runtime.setConnectTimeout(3000);
        runtime.setReadTimeout(3000);

        return client.callApi(params, request, runtime);
    }
}