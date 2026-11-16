package com.aliyuncs.kms.secretsmanager.client.v2.mauth.authenticator;

public interface Authenticator {
    Identity getIdentity() throws Exception;
}
