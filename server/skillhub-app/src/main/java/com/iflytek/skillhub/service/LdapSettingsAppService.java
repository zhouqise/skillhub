package com.iflytek.skillhub.service;

import com.iflytek.skillhub.auth.ldap.*;
import com.iflytek.skillhub.auth.repository.IdentityBindingRepository;
import com.iflytek.skillhub.auth.settings.SystemSetting;
import com.iflytek.skillhub.auth.settings.SystemSettingRepository;
import com.iflytek.skillhub.auth.federation.adapter.RemoteIdentityIoExecutor;
import com.iflytek.skillhub.domain.audit.AuditDetail;
import com.iflytek.skillhub.domain.audit.AuditLogService;
import com.iflytek.skillhub.domain.shared.exception.DomainBadRequestException;
import com.iflytek.skillhub.domain.shared.exception.DomainConflictException;
import com.iflytek.skillhub.dto.LdapSettingsResponse;
import com.iflytek.skillhub.dto.LdapSettingsUpdateRequest;
import com.iflytek.skillhub.observability.RequestIdAccessor;
import javax.naming.directory.DirContext;
import javax.naming.ldap.LdapName;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class LdapSettingsAppService {
    private final SystemSettingRepository repository;
    private final LdapSettingsService settings;
    private final LdapSecretCipher cipher;
    private final IdentityBindingRepository identities;
    private final RemoteIdentityIoExecutor remoteIo;
    private final AuditLogService audit;
    private final RequestIdAccessor requestIds;
    public LdapSettingsAppService(SystemSettingRepository repository, LdapSettingsService settings,
            LdapSecretCipher cipher, IdentityBindingRepository identities, RemoteIdentityIoExecutor remoteIo,
            AuditLogService audit, RequestIdAccessor requestIds) {
        this.repository = repository; this.settings = settings; this.cipher = cipher;
        this.identities = identities; this.remoteIo = remoteIo; this.audit = audit; this.requestIds = requestIds;
    }
    public LdapSettingsResponse get() {
        SystemSetting row = repository.findBySettingKey(LdapSettingsService.KEY).orElse(null);
        LdapAuthProperties config = row == null ? settings.defaults() : settings.publicConfiguration(row);
        return response(row, config);
    }
    @Transactional
    public LdapSettingsResponse save(LdapSettingsUpdateRequest request, String actor, AuditRequestContext context) {
        SystemSetting row = repository.findBySettingKey(LdapSettingsService.KEY).orElse(null);
        checkVersion(row, request.version());
        LdapAuthProperties previous = previous(row, request.configuration());
        LdapAuthProperties config = prepare(request.configuration(), previous);
        // Reject coordinate changes while enabled as well: an in-flight authentication may still create a binding.
        boolean locked = identityLocked(row, previous);
        if (locked && (!previous.getDirectoryId().equals(config.getDirectoryId())
                || !previous.getSubjectAttribute().equals(config.getSubjectAttribute()))) {
            throw new DomainConflictException("error.auth.ldap.identityLocked");
        }
        if (!cipher.configured()) throw new DomainBadRequestException("error.auth.ldap.encryptionMissing");
        java.util.Map<String, Object> values = new java.util.HashMap<>(settings.encode(config));
        // Permanently freeze coordinates after enabling, covering authentication racing with disable/save.
        values.put("identityLocked", locked || config.isEnabled());
        if (row == null) row = new SystemSetting(LdapSettingsService.KEY, values);
        row.update(values, actor);
        try { repository.saveAndFlush(row); }
        catch (org.springframework.dao.DataIntegrityViolationException conflict) {
            throw new DomainConflictException("error.system.settings.version.conflict");
        }
        record(actor, "LDAP_SETTINGS_UPDATE", row.getVersion(), context, true);
        return response(row, config);
    }
    public void test(LdapSettingsUpdateRequest request, String actor, AuditRequestContext context) {
        SystemSetting row = repository.findBySettingKey(LdapSettingsService.KEY).orElse(null);
        checkVersion(row, request.version());
        LdapAuthProperties previous = previous(row, request.configuration());
        LdapAuthProperties config = prepare(request.configuration(), previous);
        config.setEnabled(true);
        validate(config);
        boolean success = remoteIo.execute(() -> probe(config));
        record(actor, "LDAP_SETTINGS_TEST", request.version(), context, success);
        if (!success) throw new DomainBadRequestException("error.auth.ldap.connectionFailed");
    }
    public static boolean probe(LdapAuthProperties config) {
        DirContext context = null;
        try {
            var source = LdapAuthenticationConfiguration.createContextSource(config);
            source.afterPropertiesSet();
            context = source.getReadOnlyContext();
            context.getAttributes(new LdapName(config.getBaseDn()).addAll(new LdapName(config.getUserSearchBase())), new String[]{"1.1"});
            return true;
        } catch (Exception failure) { return false; }
        finally { if (context != null) try { context.close(); } catch (Exception ignored) { } }
    }
    private LdapAuthProperties previous(SystemSetting row, LdapAuthProperties incoming) {
        if (row == null) return settings.defaults();
        // Replacement must remain possible after restoring a lost deployment encryption key.
        if (incoming.getBindPassword() != null && !incoming.getBindPassword().isEmpty()) return settings.publicConfiguration(row);
        try { return settings.decode(row); }
        catch (IllegalStateException unavailable) { throw new DomainBadRequestException("error.auth.ldap.secretUnreadable"); }
    }
    private LdapAuthProperties prepare(LdapAuthProperties config, LdapAuthProperties previous) {
        if (config.getBindPassword() == null || config.getBindPassword().isEmpty()) config.setBindPassword(previous.getBindPassword());
        validate(config);
        return config;
    }
    private void validate(LdapAuthProperties config) {
        try { config.validate(); }
        catch (IllegalArgumentException invalid) { throw new DomainBadRequestException("error.auth.ldap.invalidConfiguration"); }
    }
    private void checkVersion(SystemSetting row, long expected) {
        if ((row == null ? -1 : row.getVersion()) != expected) throw new DomainConflictException("error.system.settings.version.conflict");
    }
    private boolean identityLocked(SystemSetting row, LdapAuthProperties config) {
        return config.isEnabled() || (row != null && Boolean.TRUE.equals(row.getValue().get("identityLocked")))
                || identities.existsByProviderCode("ldap");
    }
    private LdapSettingsResponse response(SystemSetting row, LdapAuthProperties config) {
        boolean passwordConfigured = row == null ? !config.getBindPassword().isEmpty()
                : !String.valueOf(row.getValue().getOrDefault("encryptedBindPassword", "")).isEmpty();
        boolean locked = identityLocked(row, config);
        config.setBindPassword("");
        return new LdapSettingsResponse(row == null ? -1 : row.getVersion(), config, passwordConfigured, cipher.configured(), locked, row == null ? "ENVIRONMENT" : "DATABASE");
    }
    private void record(String actor, String action, long version, AuditRequestContext context, boolean success) {
        audit.record(actor, action, "SYSTEM_SETTING", null, requestIds.current(), context.clientIp(), context.userAgent(),
                AuditDetail.builder().put("version", version).put("success", success).build());
    }
}
