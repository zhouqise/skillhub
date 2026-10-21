package com.iflytek.skillhub.dto;
import com.iflytek.skillhub.auth.ldap.LdapAuthProperties;
import jakarta.validation.constraints.NotNull;
public record LdapSettingsUpdateRequest(@NotNull @jakarta.validation.constraints.Min(-1) Long version, @NotNull LdapAuthProperties configuration) {}
