package com.iflytek.skillhub.config;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class LdapAuthCompatibilityConfigurationTest {
    @Test
    void cannotEnableLdapWithoutDirectEntry() {
        assertThatThrownBy(() -> new LdapAuthCompatibilityConfiguration(new DirectAuthProperties(), new OAuth2ClientProperties()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.NullAndEmptySource
    @org.junit.jupiter.params.provider.ValueSource(strings = {"existing-client", "placeholder-client"})
    void cannotReuseOauthIdentityNamespace(String clientId) {
        DirectAuthProperties direct = new DirectAuthProperties();
        direct.setEnabled(true);
        OAuth2ClientProperties oauth = new OAuth2ClientProperties();
        OAuth2ClientProperties.Registration registration = new OAuth2ClientProperties.Registration();
        registration.setClientId(clientId);
        oauth.getRegistration().put("ldap", registration);
        assertThatThrownBy(() -> new LdapAuthCompatibilityConfiguration(direct, oauth))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
