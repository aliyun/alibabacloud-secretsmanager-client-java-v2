package com.aliyuncs.kms.secretsmanager.client.v2.mauth.exchanger;

public class ExchangeResult {

    private String tokenType;
    private String tokenValue;

    public String getTokenType() {
        return tokenType;
    }

    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
    }

    public String getTokenValue() {
        return tokenValue;
    }

    public void setTokenValue(String tokenValue) {
        this.tokenValue = tokenValue;
    }
}
