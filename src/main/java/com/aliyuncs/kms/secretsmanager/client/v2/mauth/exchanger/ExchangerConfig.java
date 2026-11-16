package com.aliyuncs.kms.secretsmanager.client.v2.mauth.exchanger;

import com.aliyuncs.kms.secretsmanager.client.v2.utils.CacheClientConstant;

public class ExchangerConfig {

    public static final String EXCHANGER_TYPE_KMS = "kms";

    private String exchangerType;
    private String kmsEndpoint;
    private String aapArn;
    private String ca;

    public String getExchangerType() {
        return exchangerType;
    }

    public void setExchangerType(String exchangerType) {
        this.exchangerType = exchangerType;
    }

    public String getKmsEndpoint() {
        return kmsEndpoint;
    }

    public void setKmsEndpoint(String kmsEndpoint) {
        this.kmsEndpoint = kmsEndpoint;
    }

    public String getAapArn() {
        return aapArn;
    }

    public void setAapArn(String aapArn) {
        this.aapArn = aapArn;
    }

    public String getCa() {
        return ca;
    }

    public void setCa(String ca) {
        this.ca = ca;
    }

    public static void validateConfig(ExchangerConfig config) {
        if (config.exchangerType == null || config.exchangerType.isEmpty()) {
            throw new IllegalArgumentException("ExchangerType is required");
        }
        if (config.exchangerType.equals(EXCHANGER_TYPE_KMS)) {
            if (config.kmsEndpoint == null || config.kmsEndpoint.isEmpty()) {
                throw new IllegalArgumentException("KmsEndpoint is required");
            }
            if (config.kmsEndpoint.endsWith(CacheClientConstant.INSTANCE_GATEWAY_DOMAIN_SUFFIX)) {
                if (config.ca == null || config.ca.isEmpty()) {
                    throw new IllegalArgumentException("use dedicate endpoint Ca is required");
                }
            }
        } else {
            throw new IllegalArgumentException("unsupported exchanger type: " + config.exchangerType);
        }
    }
}
