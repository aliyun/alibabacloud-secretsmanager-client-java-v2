package com.aliyuncs.kms.secretsmanager.client.v2.mauth;

import java.util.Date;

public class AuthToken {

    public static final String AUTH_TOKEN_TYPE_CLIENT_KEY = "ClientKey";

    private String tokenType;
    private String tokenKeyId;
    private String tokenValue;
    private Date expiresAt;

    public String getTokenType() {
        return tokenType;
    }

    public void setTokenType(String tokenType) {
        this.tokenType = tokenType;
    }

    public String getTokenKeyId() {
        return tokenKeyId;
    }

    public void setTokenKeyId(String tokenKeyId) {
        this.tokenKeyId = tokenKeyId;
    }

    public String getTokenValue() {
        return tokenValue;
    }

    public void setTokenValue(String tokenValue) {
        this.tokenValue = tokenValue;
    }

    public Date getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(Date expiresAt) {
        this.expiresAt = expiresAt;
    }
}
