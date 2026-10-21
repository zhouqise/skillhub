package com.iflytek.skillhub.auth.ldap;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.iflytek.skillhub.auth.settings.SystemSetting;
import com.iflytek.skillhub.auth.settings.SystemSettingRepository;
import java.util.HashMap;
import java.util.Map;
import org.springframework.stereotype.Service;

/** Each call returns a detached configuration snapshot; no mutable connection is shared. */
@Service
public class LdapSettingsService {
    public static final String KEY = "auth.ldap";
    private final SystemSettingRepository repository;
    private final LdapAuthProperties defaults;
    private final ObjectMapper mapper;
    private final LdapSecretCipher cipher;
    public LdapSettingsService(SystemSettingRepository repository, LdapAuthProperties defaults,
                               ObjectMapper mapper, LdapSecretCipher cipher) {
        this.repository = repository; this.defaults = defaults; this.mapper = mapper; this.cipher = cipher;
    }
    public LdapAuthProperties current() {
        return repository.findBySettingKey(KEY).map(this::decode).orElseGet(this::defaults);
    }
    public boolean enabled() {
        // Availability discovery does not need to decrypt a secret or contact the directory.
        return repository.findBySettingKey(KEY).map(s -> Boolean.TRUE.equals(s.getValue().get("enabled")))
                .orElse(defaults.isEnabled());
    }
    public LdapAuthProperties defaults() {
        LdapAuthProperties copy = mapper.convertValue(defaults, LdapAuthProperties.class);
        copy.setBindPassword(defaults.getBindPassword());
        return copy;
    }
    public LdapAuthProperties publicConfiguration(SystemSetting setting) {
        Map<String, Object> values = new HashMap<>(setting.getValue());
        values.remove("encryptedBindPassword");
        values.remove("identityLocked");
        return mapper.convertValue(values, LdapAuthProperties.class);
    }
    public LdapAuthProperties decode(SystemSetting setting) {
        LdapAuthProperties properties = publicConfiguration(setting);
        properties.setBindPassword(cipher.decrypt((String) setting.getValue().getOrDefault("encryptedBindPassword", "")));
        return properties;
    }
    public Map<String, Object> encode(LdapAuthProperties properties) {
        Map<String, Object> values = mapper.convertValue(properties, new com.fasterxml.jackson.core.type.TypeReference<Map<String, Object>>() {});
        values.remove("bindPassword");
        values.put("encryptedBindPassword", cipher.encrypt(properties.getBindPassword()));
        return values;
    }
}
