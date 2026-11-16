# Changelog

### Release 2.0.2 (November 11, 2026)
* Upgrade SDK version to 2.0.2
* Add cloud-native authentication: ECS instance identity, ACK OIDC JWT, and ClientKey
* Add bearer-token based GetSecretValue with request signing
* Refine cross-region failover to trigger only on connection-related exceptions
* Add documentation for cloud-native authentication configuration

### Release 2.0.1 (September 28, 2026)
* Patch security vulnerabilities in tea and tea-openapi dependencies

### Release 2.0.0 (November 5, 2025)
* Initial release of Alibaba Secrets Manager Client V2 for Java
* Support for multiple authentication methods including AK/SK, ECS RAM Role, and OIDC Role ARN
* Memory and file-based caching mechanisms for improved performance
* Cross-region disaster recovery support
* Default backoff strategy with customizable options
* Support for Aliyun default credential chain
