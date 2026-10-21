package com.iflytek.skillhub.auth.ldap;

import com.iflytek.skillhub.auth.federation.adapter.RemoteIdentityIoExecutor;
import com.iflytek.skillhub.auth.identity.ExternalIdentityAuthenticationService;
import java.util.HashMap;
import java.util.Map;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.support.DefaultTlsDirContextAuthenticationStrategy;
import org.springframework.ldap.core.support.LdapContextSource;

/**
 * 动态装配 LDAP 认证提供方，每次认证使用独立配置快照。
 *
 * <p>不启用连接池、不跟随引用；TLS 握手失败不会回退明文，信任由 JVM truststore 提供。
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(LdapAuthProperties.class)
public class LdapAuthenticationConfiguration {
    public static LdapContextSource createContextSource(LdapAuthProperties properties) {
        properties.validate();
        LdapContextSource source = new LdapContextSource();
        source.setUrl(properties.getUrl());
        // 根上下文让搜索与绑定后的读取始终使用完整 DN，避免混用相对 DN。
        source.setBase("");
        source.setUserDn(properties.getBindDn());
        source.setPassword(properties.getBindPassword());
        source.setPooled(false);
        source.setReferral("throw");
        Map<String, Object> environment = new HashMap<>();
        environment.put("com.sun.jndi.ldap.connect.timeout", Integer.toString(properties.getConnectTimeoutMs()));
        environment.put("com.sun.jndi.ldap.read.timeout", Integer.toString(properties.getReadTimeoutMs()));
        environment.put("java.naming.ldap.attributes.binary", "objectGUID");
        source.setBaseEnvironmentProperties(environment);
        if ("STARTTLS".equals(properties.getTlsMode())) {
            DefaultTlsDirContextAuthenticationStrategy strategy = new DefaultTlsDirContextAuthenticationStrategy();
            strategy.setShutdownTlsGracefully(true);
            source.setAuthenticationStrategy(strategy);
        }
        return source;
    }

    @Bean
    public LdapDirectoryAuthenticator ldapDirectoryAuthenticator(LdapSettingsService settings,
            RemoteIdentityIoExecutor remoteIdentityIoExecutor) {
        return new LdapDirectoryAuthenticator(settings::current, remoteIdentityIoExecutor);
    }

    @Bean
    public LdapDirectAuthProvider ldapDirectAuthProvider(LdapDirectoryAuthenticator authenticator,
            ExternalIdentityAuthenticationService identityService, LdapSettingsService settings) {
        return new LdapDirectAuthProvider(authenticator, identityService) {
            @Override public boolean enabled() { return settings.enabled(); }
        };
    }
}
