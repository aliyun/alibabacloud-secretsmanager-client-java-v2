package com.aliyuncs.kms.secretsmanager.client.v2.utils;

import com.aliyun.credentials.models.CredentialModel;
import com.aliyun.credentials.provider.AlibabaCloudCredentialsProvider;
import com.aliyun.credentials.provider.EcsRamRoleCredentialProvider;
import com.aliyun.credentials.provider.OIDCRoleArnCredentialProvider;
import com.aliyun.credentials.provider.StaticCredentialsProvider;
import com.aliyun.tea.utils.StringUtils;
import com.aliyun.tea.utils.Validate;
import com.aliyuncs.kms.secretsmanager.client.v2.mauth.config.AuthConfig;
import com.aliyuncs.kms.secretsmanager.client.v2.model.RegionInfo;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import java.util.*;

public class CredentialsProviderUtils {

    private static final Map<String, String> AUTH_METHOD_MAP = new HashMap<String, String>() {{
        put(CacheClientConstant.VARIABLE_CREDENTIALS_TYPE_ECS, AuthConfig.ECS_INSTANCE_IDENTITY);
        put(CacheClientConstant.VARIABLE_CREDENTIALS_TYPE_ACK, AuthConfig.ACK_OIDC_JWT);
        put(CacheClientConstant.VARIABLE_CREDENTIALS_TYPE_CLIENT_KEY, AuthConfig.CLIENT_KEY);
    }};
    private CredentialsProviderUtils() {
        // do nothing
    }

    /**
     * 使用AccessKey创建阿里云凭证信息
     *
     * @param accessKeyId     AccessKey ID
     * @param accessKeySecret AccessKey Secret
     * @return AlibabaCloudCredentialsProvider对象
     */
    public static AlibabaCloudCredentialsProvider withAccessKey(String accessKeyId, String accessKeySecret) {
        return StaticCredentialsProvider.builder().credential(CredentialModel.builder().accessKeyId(Validate.notNull(accessKeyId, "AccessKeyId must not be null.", new Object[0])).accessKeySecret((String) Validate.notNull(accessKeySecret, "AccessKeySecret must not be null.", new Object[0])).type("access_key").build()).build();
    }

    /**
     * 使用ECS RAM角色创建阿里云凭证信息
     *
     * @param roleName ECS RAM角色名称
     * @return AlibabaCloudCredentialsProvider对象
     */
    public static AlibabaCloudCredentialsProvider withEcsRamRole(String roleName) {
        return EcsRamRoleCredentialProvider.builder().roleName(roleName).build();
    }

    /**
     * 使用OIDC角色ARN创建阿里云凭证信息
     *
     * @param roleSessionName       角色会话名称
     * @param roleArn               角色ARN
     * @param oidcProviderArn       OIDC提供者ARN
     * @param policy                策略
     * @param STSEndpoint           STS域名
     * @param oidcTokenFilePath     OIDC令牌文件路径
     * @param roleSessionExpiration 角色会话过期时间
     * @param stsRegionId           地域ID
     * @return AlibabaCloudCredentialsProvider对象
     */
    public static AlibabaCloudCredentialsProvider withOIDCRoleArn(String roleSessionName, String roleArn, String oidcProviderArn, String oidcTokenFilePath, String policy, String STSEndpoint,
                                                                  Integer roleSessionExpiration, String stsRegionId) {
        return OIDCRoleArnCredentialProvider.builder()
                .durationSeconds(roleSessionExpiration)
                .roleArn(roleArn)
                .roleSessionName(roleSessionName)
                .oidcProviderArn(oidcProviderArn)
                .oidcTokenFilePath(oidcTokenFilePath)
                .policy(policy)
                .STSEndpoint(STSEndpoint)
                .stsRegionId(stsRegionId)
                .build();
    }

    /**
     * 使用OIDC角色ARN创建阿里云凭证信息
     *
     * @param roleArn           角色ARN
     * @param oidcProviderArn   OIDC提供者ARN
     * @param oidcTokenFilePath OIDC令牌文件路径
     * @return AlibabaCloudCredentialsProvider对象
     */
    public static AlibabaCloudCredentialsProvider withOIDCRoleArn(String roleArn, String oidcProviderArn, String oidcTokenFilePath) {
        return OIDCRoleArnCredentialProvider.builder()
                .roleArn(roleArn)
                .oidcProviderArn(oidcProviderArn)
                .oidcTokenFilePath(oidcTokenFilePath)
                .build();
    }

    /**
     * 通用凭证信息初始化方法
     *
     * @param map            Map对象（可以是环境变量或配置文件属性）
     * @param sourceTypeName 数据源类型（"config" 或 "env"）
     * @return AlibabaCloudCredentialsProvider对象
     */
    public static AlibabaCloudCredentialsProvider initCredentialsProvider(
            Map<String, String> map,
            String sourceTypeName) {

        String credentialsType = map.get(CacheClientConstant.VARIABLE_CREDENTIALS_TYPE_KEY);
        if (credentialsType == null || credentialsType.isEmpty()) {
            return null;
        }

        AlibabaCloudCredentialsProvider provider;
        switch (credentialsType) {
            case "ak":
                String accessKeyId = map.get(CacheClientConstant.VARIABLE_CREDENTIALS_ACCESS_KEY_ID_KEY);
                String accessSecret = map.get(CacheClientConstant.VARIABLE_CREDENTIALS_ACCESS_SECRET_KEY);
                if (accessKeyId == null || accessKeyId.isEmpty()) {
                    throw new IllegalArgumentException(String.format(CacheClientConstant.CHECK_PARAM_ERROR_MESSAGE, sourceTypeName, CacheClientConstant.VARIABLE_CREDENTIALS_ACCESS_KEY_ID_KEY));
                }
                if (accessSecret == null || accessSecret.isEmpty()) {
                    throw new IllegalArgumentException(String.format(CacheClientConstant.CHECK_PARAM_ERROR_MESSAGE, sourceTypeName, CacheClientConstant.VARIABLE_CREDENTIALS_ACCESS_SECRET_KEY));
                }
                provider = CredentialsProviderUtils.withAccessKey(accessKeyId, accessSecret);
                break;
            case "ecs_ram_role":
                String roleName = map.get(CacheClientConstant.VARIABLE_CREDENTIALS_ROLE_NAME_KEY);
                if (roleName == null || roleName.isEmpty()) {
                    throw new IllegalArgumentException(String.format(CacheClientConstant.CHECK_PARAM_ERROR_MESSAGE, sourceTypeName, CacheClientConstant.VARIABLE_CREDENTIALS_ROLE_NAME_KEY));
                }
                provider = CredentialsProviderUtils.withEcsRamRole(roleName);
                break;
            case "oidc_role_arn":
                Integer roleSessionExpiration = TypeUtils.parseInteger(map.get(CacheClientConstant.VARIABLE_CREDENTIALS_OIDC_DURATION_SECONDS_KEY));
                String roleSessionName = TypeUtils.parseString(map.get(CacheClientConstant.VARIABLE_CREDENTIALS_OIDC_ROLE_SESSION_NAME_KEY));
                String roleArn = TypeUtils.parseString(map.get(CacheClientConstant.VARIABLE_CREDENTIALS_OIDC_ROLE_ARN_KEY));
                String oidcProviderArn = TypeUtils.parseString(map.get(CacheClientConstant.VARIABLE_CREDENTIALS_OIDC_PROVIDER_ARN_KEY));
                String oidcTokenFilePath = TypeUtils.parseString(map.get(CacheClientConstant.VARIABLE_CREDENTIALS_OIDC_TOKEN_FILE_PATH_KEY));
                String stsRegionId = TypeUtils.parseString(map.get(CacheClientConstant.VARIABLE_CREDENTIALS_OIDC_STS_REGION_ID_KEY));
                String policy = TypeUtils.parseString(map.get(CacheClientConstant.VARIABLE_CREDENTIALS_OIDC_POLICY_KEY));
                String stsEndpoint = TypeUtils.parseString(map.get(CacheClientConstant.VARIABLE_CREDENTIALS_OIDC_STS_ENDPOINT_KEY));
                provider = CredentialsProviderUtils.withOIDCRoleArn(roleSessionName, roleArn, oidcProviderArn, oidcTokenFilePath, policy, stsEndpoint, roleSessionExpiration, stsRegionId);
                break;
            case CacheClientConstant.VARIABLE_CREDENTIALS_TYPE_ECS:
            case CacheClientConstant.VARIABLE_CREDENTIALS_TYPE_ACK:
            case CacheClientConstant.VARIABLE_CREDENTIALS_TYPE_CLIENT_KEY:
                provider = null;
                break;
            default:
                throw new IllegalArgumentException(String.format("%s credentials type[%s] is illegal", sourceTypeName, credentialsType));
        }
        return provider;
    }

    /**
     * 从配置Map初始化MAuth配置
     *
     * @param map            配置Map
     * @param sourceTypeName 配置来源名称
     * @return AuthConfig对象
     */
    public static AuthConfig initMAuthConfig(Map<String, String> map, String sourceTypeName) {
        String credentialsType = map.get(CacheClientConstant.VARIABLE_CREDENTIALS_TYPE_KEY);
        if (StringUtils.isEmpty(credentialsType)) {
            return null;
        }
        AuthConfig authConfig = new AuthConfig();
        authConfig.setAuthMethod(AUTH_METHOD_MAP.get(credentialsType));
        authConfig.setAapArn(map.get(CacheClientConstant.VARIABLE_AAP_ARN_KEY));
        authConfig.setTokenPath(map.get(CacheClientConstant.VARIABLE_TOKEN_PATH_KEY));
        authConfig.setClientKeyConfigPath(map.get(CacheClientConstant.VARIABLE_CLIENT_KEY_CONFIG_PATH_KEY));

        String clientKeyPassword = map.get(CacheClientConstant.VARIABLE_CLIENT_KEY_PASSWORD_KEY);
        String clientKeyPasswordEnvName = map.get(CacheClientConstant.VARIABLE_CLIENT_KEY_PASSWORD_ENV_KEY);
        if (!StringUtils.isEmpty(clientKeyPasswordEnvName)) {
            String envPassword = System.getenv(clientKeyPasswordEnvName);
            if (!StringUtils.isEmpty(envPassword)) {
                clientKeyPassword = envPassword;
            }
        }
        authConfig.setClientKeyPassword(clientKeyPassword);
        authConfig.setClientKeyPasswordPath(map.get(CacheClientConstant.VARIABLE_CLIENT_KEY_PASSWORD_PATH_KEY));

        switch (credentialsType) {
            case CacheClientConstant.VARIABLE_CREDENTIALS_TYPE_ACK:
                if (StringUtils.isEmpty(authConfig.getAapArn())) {
                    throw new IllegalArgumentException(String.format(CacheClientConstant.CHECK_PARAM_ERROR_MESSAGE, sourceTypeName, CacheClientConstant.VARIABLE_AAP_ARN_KEY));
                }
                if (StringUtils.isEmpty(authConfig.getTokenPath())) {
                    throw new IllegalArgumentException(String.format(CacheClientConstant.CHECK_PARAM_ERROR_MESSAGE, sourceTypeName, CacheClientConstant.VARIABLE_TOKEN_PATH_KEY));
                }
                break;
            case CacheClientConstant.VARIABLE_CREDENTIALS_TYPE_ECS:
                if (StringUtils.isEmpty(authConfig.getAapArn())) {
                    throw new IllegalArgumentException(String.format(CacheClientConstant.CHECK_PARAM_ERROR_MESSAGE, sourceTypeName, CacheClientConstant.VARIABLE_AAP_ARN_KEY));
                }
                break;
            case CacheClientConstant.VARIABLE_CREDENTIALS_TYPE_CLIENT_KEY:
                if (StringUtils.isEmpty(authConfig.getClientKeyConfigPath())) {
                    throw new IllegalArgumentException(String.format(CacheClientConstant.CHECK_PARAM_ERROR_MESSAGE, sourceTypeName, CacheClientConstant.VARIABLE_CLIENT_KEY_CONFIG_PATH_KEY));
                }
                if (ConfigUtils.getFileByPath(authConfig.getClientKeyConfigPath()) == null) {
                    throw new IllegalArgumentException(String.format(CacheClientConstant.CHECK_FILE_NOT_EXISTS_ERROR_MESSAGE, sourceTypeName, CacheClientConstant.VARIABLE_CLIENT_KEY_CONFIG_PATH_KEY));
                }
                if (StringUtils.isEmpty(authConfig.getClientKeyPassword())
                        && StringUtils.isEmpty(authConfig.getClientKeyPasswordPath())) {
                    throw new IllegalArgumentException(String.format("%s credentials missing required parameters[%s or %s]", sourceTypeName, CacheClientConstant.VARIABLE_CLIENT_KEY_PASSWORD_ENV_KEY, CacheClientConstant.VARIABLE_CLIENT_KEY_PASSWORD_PATH_KEY));
                }
                if (!StringUtils.isEmpty(authConfig.getClientKeyPasswordPath())
                        && ConfigUtils.getFileByPath(authConfig.getClientKeyPasswordPath()) == null) {
                    throw new IllegalArgumentException(String.format(CacheClientConstant.CHECK_FILE_NOT_EXISTS_ERROR_MESSAGE, sourceTypeName, CacheClientConstant.VARIABLE_CLIENT_KEY_PASSWORD_PATH_KEY));
                }
                break;
            default:
                return null;
        }

        return authConfig;
    }

    /**
     * 从环境变量初始化MAuth配置
     *
     * @param envMap 环境变量Map
     * @return AuthConfig对象
     */
    public static AuthConfig initMAuthConfigFromEnv(Map<String, String> envMap) {
        return CredentialsProviderUtils.initMAuthConfig(envMap, CacheClientConstant.SOURCE_TYPE_ENV);
    }

    /**
     * 从配置文件初始化MAuth配置
     *
     * @param properties 配置属性
     * @return AuthConfig对象
     */
    public static AuthConfig initMAuthConfigFromConfig(Properties properties) {
        Map<String, String> map = new HashMap<>();
        for (Map.Entry<Object, Object> entry : properties.entrySet()) {
            map.put((String) entry.getKey(), (String) entry.getValue());
        }
        return CredentialsProviderUtils.initMAuthConfig(map, CacheClientConstant.SOURCE_TYPE_CONFIG);
    }

    /**
     * 从环境变量初始化凭证信息
     *
     * @param envMap 环境变量Map
     * @return AlibabaCloudCredentialsProvider对象
     */
    public static AlibabaCloudCredentialsProvider initCredentialsProviderFromEnv(Map<String, String> envMap) {
        return CredentialsProviderUtils.initCredentialsProvider(envMap, CacheClientConstant.SOURCE_TYPE_ENV);
    }

    /**
     * 从配置文件初始化凭证信息
     *
     * @param properties 配置属性
     * @return AlibabaCloudCredentialsProvider对象
     */
    public static AlibabaCloudCredentialsProvider initCredentialsProviderFromConfig(Properties properties) {
        Map<String, String> map = new HashMap<>();
        for (Map.Entry<Object, Object> entry : properties.entrySet()) {
            map.put((String) entry.getKey(), (String) entry.getValue());
        }
        return CredentialsProviderUtils.initCredentialsProvider(map, CacheClientConstant.SOURCE_TYPE_CONFIG);
    }

    /**
     * 从配置属性或环境变量初始化KMS地域信息列表
     *
     * @param properties 配置属性
     * @param sourceType 配置属性来源("config" 或 "env")
     */
    public static List<RegionInfo> initKmsRegions(Properties properties, String sourceType) {
        List<RegionInfo> regionInfoList = new ArrayList<>();
        String regionIds = properties.getProperty(CacheClientConstant.VARIABLE_CACHE_CLIENT_REGION_ID_KEY);
        if (!StringUtils.isEmpty(regionIds)) {
            try {
                List<Map<String, Object>> list = new Gson().fromJson(regionIds, new TypeToken<List<Map<String, Object>>>() {
                }.getType());
                for (Map<String, Object> map : list) {
                    RegionInfo regionInfo = new RegionInfo();
                    regionInfo.setEndpoint(TypeUtils.parseString(map.get(CacheClientConstant.VARIABLE_REGION_ENDPOINT_NAME_KEY)));
                    regionInfo.setRegionId(TypeUtils.parseString(map.get(CacheClientConstant.VARIABLE_REGION_REGION_ID_NAME_KEY)));
                    regionInfo.setVpc(TypeUtils.parseBoolean(map.get(CacheClientConstant.VARIABLE_REGION_VPC_NAME_KEY)));
                    regionInfo.setCaFilePath(TypeUtils.parseString(map.get(CacheClientConstant.VARIABLE_REGION_CA_FILE_PATH_NAME_KEY)));
                    regionInfoList.add(regionInfo);
                }
            } catch (Exception e) {
                throw new IllegalArgumentException(String.format("%s credentials param[%s] is illegal", sourceType, CacheClientConstant.VARIABLE_CACHE_CLIENT_REGION_ID_KEY));
            }
        }
        return regionInfoList;
    }
}
