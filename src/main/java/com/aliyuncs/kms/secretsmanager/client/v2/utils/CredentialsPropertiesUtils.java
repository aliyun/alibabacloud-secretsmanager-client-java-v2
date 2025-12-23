package com.aliyuncs.kms.secretsmanager.client.v2.utils;

import com.aliyun.credentials.provider.AlibabaCloudCredentialsProvider;
import com.aliyun.tea.utils.StringUtils;
import com.aliyuncs.kms.secretsmanager.client.v2.model.CredentialsProperties;

import java.util.*;

public class CredentialsPropertiesUtils {


    private CredentialsPropertiesUtils() {
        // do nothing
    }

    /**
     * 加载凭据配置属性
     *
     * @param fileName 配置文件名
     * @return 凭据配置属性对象
     */
    public static CredentialsProperties loadCredentialsProperties(String fileName) {
        if (StringUtils.isEmpty(fileName)) {
            fileName = CacheClientConstant.CREDENTIALS_PROPERTIES_CONFIG_NAME;
        }
        Properties properties = ConfigUtils.loadConfig(fileName);
        CredentialsProperties credentialsProperties = new CredentialsProperties();
        credentialsProperties.setSourceProperties(properties);
        if (properties != null && !properties.isEmpty()) {
            initKmsRegionsFromConfig(credentialsProperties);
            initCredentialsProvider(credentialsProperties);
            return credentialsProperties;
        } else {
            return null;
        }
    }

    /**
     * 从配置属性或环境变量初始化KMS地域信息列表
     *
     * @param credentialsProperties 凭据配置属性
     */
    private static void initKmsRegionsFromConfig(CredentialsProperties credentialsProperties) {
        credentialsProperties.setRegionInfoList(CredentialsProviderUtils.initKmsRegions(credentialsProperties.getSourceProperties(), CacheClientConstant.SOURCE_TYPE_CONFIG));
    }


    /**
     * 初始化凭凭证信息
     *
     * @param credentialsProperties 凭据配置属性
     */
    private static void initCredentialsProvider(CredentialsProperties credentialsProperties) {
        AlibabaCloudCredentialsProvider credentialsProvider = CredentialsProviderUtils.initCredentialsProviderFromConfig(credentialsProperties.getSourceProperties());
        credentialsProperties.setProvider(credentialsProvider);
    }
}