package com.aliyuncs.kms.secretsmanager.client.v2.mauth.config;

import com.aliyuncs.kms.secretsmanager.client.v2.utils.ConfigUtils;

public class AuthConfig {

    public static final String ECS_INSTANCE_IDENTITY = "ECSInstanceIdentity";
    public static final String ACK_OIDC_JWT = "ACKOidcJwt";
    public static final String CLIENT_KEY = "ClientKey";

    private String authMethod;
    private String aapArn;
    private String tokenPath;
    private String clientKeyConfigPath;
    private String clientKeyPassword;
    private String clientKeyPasswordPath;
    private String kmsEndpoint;
    private String ca;

    public String getAuthMethod() {
        return authMethod;
    }

    public void setAuthMethod(String authMethod) {
        this.authMethod = authMethod;
    }

    public String getAapArn() {
        return aapArn;
    }

    public void setAapArn(String aapArn) {
        this.aapArn = aapArn;
    }

    public String getTokenPath() {
        return tokenPath;
    }

    public void setTokenPath(String tokenPath) {
        this.tokenPath = tokenPath;
    }

    public String getClientKeyConfigPath() {
        return clientKeyConfigPath;
    }

    public void setClientKeyConfigPath(String clientKeyConfigPath) {
        this.clientKeyConfigPath = clientKeyConfigPath;
    }

    public String getClientKeyPassword() {
        return clientKeyPassword;
    }

    public void setClientKeyPassword(String clientKeyPassword) {
        this.clientKeyPassword = clientKeyPassword;
    }

    public String getClientKeyPasswordPath() {
        return clientKeyPasswordPath;
    }

    public void setClientKeyPasswordPath(String clientKeyPasswordPath) {
        this.clientKeyPasswordPath = clientKeyPasswordPath;
    }

    public String getKmsEndpoint() {
        return kmsEndpoint;
    }

    public void setKmsEndpoint(String kmsEndpoint) {
        this.kmsEndpoint = kmsEndpoint;
    }

    public String getCa() {
        return ca;
    }

    public void setCa(String ca) {
        this.ca = ca;
    }

    public void validate() {
        if (authMethod == null || authMethod.isEmpty()) {
            throw new IllegalArgumentException("AuthMethod is required");
        }
        if (kmsEndpoint == null || kmsEndpoint.isEmpty()) {
            throw new IllegalArgumentException("KmsEndpoint is required");
        }
        switch (authMethod) {
            case ACK_OIDC_JWT:
                if (aapArn == null || aapArn.isEmpty()) {
                    throw new IllegalArgumentException("AapArn is required for ACK OIDC JWT authentication");
                }
                break;
            case ECS_INSTANCE_IDENTITY:
                if (aapArn == null || aapArn.isEmpty()) {
                    throw new IllegalArgumentException("AapArn is required for ECS Instance Identity authentication");
                }
                break;
            case CLIENT_KEY:
                if (clientKeyConfigPath == null || clientKeyConfigPath.isEmpty()) {
                    throw new IllegalArgumentException("ClientKeyConfigPath is required for Client Key authentication");
                }
                if (ConfigUtils.getFileByPath(clientKeyConfigPath) == null) {
                    throw new IllegalArgumentException("client key config file does not exist: " + clientKeyConfigPath);
                }
                if (clientKeyPassword == null || clientKeyPassword.isEmpty()) {
                    if (clientKeyPasswordPath == null || clientKeyPasswordPath.isEmpty()) {
                        throw new IllegalArgumentException("ClientKeyPassword or ClientKeyPasswordPath is required for Client Key authentication");
                    }
                    if (ConfigUtils.getFileByPath(clientKeyPasswordPath) == null) {
                        throw new IllegalArgumentException("client key password file does not exist: " + clientKeyPasswordPath);
                    }
                }
                break;
            default:
                throw new IllegalArgumentException("unsupported authentication method: " + authMethod);
        }
    }
}
