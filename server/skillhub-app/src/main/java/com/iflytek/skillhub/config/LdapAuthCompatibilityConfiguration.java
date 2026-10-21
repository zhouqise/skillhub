package com.iflytek.skillhub.config;

import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.context.annotation.Configuration;

/**
 * 校验 LDAP 与现有登录装配的兼容性，不访问外部目录。
 *
 * <p>LDAP 使用独立开关，不能与任何 OAuth 注册共享 ldap 身份坐标。
 */
@Configuration(proxyBeanMethods = false)
public class LdapAuthCompatibilityConfiguration {
    public LdapAuthCompatibilityConfiguration(DirectAuthProperties directAuthProperties,
            OAuth2ClientProperties oAuth2ClientProperties) {
        OAuth2ClientProperties.Registration registration = oAuth2ClientProperties.getRegistration().get("ldap");
        if (registration != null) {
            throw new IllegalArgumentException("LDAP cannot share an OAuth registration named ldap");
        }
    }
}
