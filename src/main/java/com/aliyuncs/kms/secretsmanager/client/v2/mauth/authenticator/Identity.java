package com.aliyuncs.kms.secretsmanager.client.v2.mauth.authenticator;

public class Identity {

    public static final String IDENTITY_TYPE_PKCS7 = "PKCS7";
    public static final String IDENTITY_TYPE_JWT = "JWT";

    private String identityType;
    private String identityValue;

    public String getIdentityType() {
        return identityType;
    }

    public void setIdentityType(String identityType) {
        this.identityType = identityType;
    }

    public String getIdentityValue() {
        return identityValue;
    }

    public void setIdentityValue(String identityValue) {
        this.identityValue = identityValue;
    }
}
