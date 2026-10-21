package com.iflytek.skillhub.dto;
import com.iflytek.skillhub.auth.ldap.LdapAuthProperties;
public record LdapSettingsResponse(@io.swagger.v3.oas.annotations.media.Schema(requiredMode = io.swagger.v3.oas.annotations.media.Schema.RequiredMode.REQUIRED) long version, @jakarta.validation.constraints.NotNull LdapAuthProperties configuration,
        boolean passwordConfigured, boolean encryptionConfigured, boolean identityLocked, String source) {}
