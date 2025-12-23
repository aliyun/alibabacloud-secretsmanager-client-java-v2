package com.aliyuncs.kms.secretsmanager.client.v2.model;


import com.aliyun.credentials.provider.AlibabaCloudCredentialsProvider;

import java.util.List;
import java.util.Properties;

public class CredentialsProperties {

    private AlibabaCloudCredentialsProvider provider;

    private List<RegionInfo> regionInfoList;

    private Properties sourceProperties;

    public AlibabaCloudCredentialsProvider getProvider() {
        return this.provider;
    }

    public void setProvider(AlibabaCloudCredentialsProvider provider) {
        this.provider = provider;
    }

    public List<RegionInfo> getRegionInfoList() {
        return this.regionInfoList;
    }

    public void setRegionInfoList(List<RegionInfo> regionInfoList) {
        this.regionInfoList = regionInfoList;
    }

    public Properties getSourceProperties() {
        return this.sourceProperties;
    }

    public void setSourceProperties(Properties sourceProperties) {
        this.sourceProperties = sourceProperties;
    }
}
