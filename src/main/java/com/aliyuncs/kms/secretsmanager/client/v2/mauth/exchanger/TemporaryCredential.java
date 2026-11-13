package com.aliyuncs.kms.secretsmanager.client.v2.mauth.exchanger;

import com.google.gson.annotations.SerializedName;

public class TemporaryCredential {

    @SerializedName("CredentialType")
    private String credentialType;

    @SerializedName("Credential")
    private String credential;

    @SerializedName("ExpiredAt")
    private String expiredAt;

    @SerializedName("Region")
    private String region;

    @SerializedName("RequestId")
    private String requestId;

    public String getCredentialType() {
        return credentialType;
    }

    public void setCredentialType(String credentialType) {
        this.credentialType = credentialType;
    }

    public String getCredential() {
        return credential;
    }

    public void setCredential(String credential) {
        this.credential = credential;
    }

    public String getExpiredAt() {
        return expiredAt;
    }

    public void setExpiredAt(String expiredAt) {
        this.expiredAt = expiredAt;
    }

    public String getRegion() {
        return region;
    }

    public void setRegion(String region) {
        this.region = region;
    }

    public String getRequestId() {
        return requestId;
    }

    public void setRequestId(String requestId) {
        this.requestId = requestId;
    }
}
