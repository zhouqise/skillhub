package com.iflytek.skillhub.auth.ldap;

import com.iflytek.skillhub.auth.federation.adapter.RemoteIdentityIoExecutor;
import com.iflytek.skillhub.auth.identity.ExternalIdentityAuthenticationService;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class LdapConfigurationTest {
    private final ApplicationContextRunner context = new ApplicationContextRunner()
            .withUserConfiguration(LdapAuthenticationConfiguration.class)
            .withBean(LdapSettingsService.class, () -> mock(LdapSettingsService.class))
            .withBean(RemoteIdentityIoExecutor.class, () -> mock(RemoteIdentityIoExecutor.class))
            .withBean(ExternalIdentityAuthenticationService.class, () -> mock(ExternalIdentityAuthenticationService.class));

    @Test
    void disabledFeatureDoesNotCreateAnyDirectoryConnection() {
        context.run(result -> assertThat(result).hasSingleBean(LdapDirectAuthProvider.class)
                .doesNotHaveBean(org.springframework.ldap.core.support.LdapContextSource.class));
    }

    @Test
    void enabledFeatureValidatesConfigurationWithoutConnectingAtStartup() {
        context.withPropertyValues("skillhub.auth.ldap.enabled=true", "skillhub.auth.ldap.directory-id=corp",
                "skillhub.auth.ldap.url=ldaps://127.0.0.1:1", "skillhub.auth.ldap.base-dn=dc=example,dc=com",
                "skillhub.auth.ldap.bind-dn=cn=reader,dc=example,dc=com", "skillhub.auth.ldap.bind-password=test-secret")
                .run(result -> assertThat(result).hasSingleBean(LdapDirectAuthProvider.class));
    }

    @Test
    void incompleteConfigurationDoesNotPreventLocalLoginStartup() {
        context.withPropertyValues("skillhub.auth.ldap.enabled=true")
                .run(result -> assertThat(result).hasNotFailed());
    }
}
