package com.aliyuncs.kms.secretsmanager.client.v2.service;

public class UserAgentManager {
    private static String userAgent;
    private static volatile int priority;
    private static String projectVersion;

    public static String getUserAgent() {
        return userAgent;
    }

    public static String getProjectVersion() {
        return projectVersion;
    }

    public static void registerUserAgent(String userAgent, int priority, String projectVersion) {
        if (priority >= UserAgentManager.priority) {
            synchronized (UserAgentManager.class) {
                if (priority >= UserAgentManager.priority) {
                    UserAgentManager.userAgent = userAgent;
                    UserAgentManager.priority = priority;
                    UserAgentManager.projectVersion = projectVersion;
                }
            }
        }
    }
}
