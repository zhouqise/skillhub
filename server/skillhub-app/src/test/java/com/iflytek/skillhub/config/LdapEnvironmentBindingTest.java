package com.iflytek.skillhub.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import com.iflytek.skillhub.auth.federation.adapter.RemoteIdentityIoExecutor;
import com.iflytek.skillhub.auth.identity.ExternalIdentityAuthenticationService;
import com.iflytek.skillhub.auth.ldap.LdapAuthProperties;
import com.iflytek.skillhub.auth.ldap.LdapAuthenticationConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.ConfigDataApplicationContextInitializer;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

class LdapEnvironmentBindingTest {
    @Test
    void applicationYamlBindsDeploymentVariablesAndPreservesFilterBraces() {
        new ApplicationContextRunner()
            .withInitializer(new ConfigDataApplicationContextInitializer())
            .withUserConfiguration(LdapAuthenticationConfiguration.class)
            .withBean(com.iflytek.skillhub.auth.ldap.LdapSettingsService.class, () -> mock(com.iflytek.skillhub.auth.ldap.LdapSettingsService.class))
            .withBean(RemoteIdentityIoExecutor.class, () -> mock(RemoteIdentityIoExecutor.class))
            .withBean(ExternalIdentityAuthenticationService.class, () -> mock(ExternalIdentityAuthenticationService.class))
            .withPropertyValues("SKILLHUB_AUTH_LDAP_ENABLED=true", "SKILLHUB_AUTH_LDAP_DIRECTORY_ID=corp",
                "SKILLHUB_AUTH_LDAP_URL=ldaps://localhost:1", "SKILLHUB_AUTH_LDAP_BASE_DN=dc=example,dc=com",
                "SKILLHUB_AUTH_LDAP_BIND_DN=cn=reader,dc=example,dc=com", "SKILLHUB_AUTH_LDAP_BIND_PASSWORD=test-secret")
            .run(context -> {
                assertThat(context).hasNotFailed();
                LdapAuthProperties properties = context.getBean(LdapAuthProperties.class);
                assertThat(properties.getDirectoryId()).isEqualTo("corp");
                assertThat(properties.getUserFilter()).isEqualTo("(uid={0})");
                assertThat(properties.getTlsMode()).isEqualTo("LDAPS");
            });
    }
}
