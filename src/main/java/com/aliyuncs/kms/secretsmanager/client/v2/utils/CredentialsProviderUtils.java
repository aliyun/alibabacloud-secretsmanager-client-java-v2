package com.aliyuncs.kms.secretsmanager.client.v2.utils;

import com.aliyun.credentials.models.CredentialModel;
import com.aliyun.credentials.provider.AlibabaCloudCredentialsProvider;
import com.aliyun.credentials.provider.EcsRamRoleCredentialProvider;
import com.aliyun.credentials.provider.OIDCRoleArnCredentialProvider;
import com.aliyun.credentials.provider.StaticCredentialsProvider;
import com.aliyun.tea.utils.StringUtils;
import com.aliyun.tea.utils.Validate;
import com.aliyuncs.kms.secretsmanager.client.v2.model.RegionInfo;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import java.util.*;

public class CredentialsProviderUtils {

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
            default:
                throw new IllegalArgumentException(String.format("%s credentials type[%s] is illegal", sourceTypeName, credentialsType));
        }
        return provider;
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