package com.iflytek.skillhub.controller.admin;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.assertj.core.api.Assertions.assertThat;
import com.iflytek.skillhub.auth.rbac.PlatformPrincipal;
import com.iflytek.skillhub.auth.settings.SystemSettingRepository;
import com.iflytek.skillhub.domain.namespace.NamespaceMemberRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest(properties = {"skillhub.auth.ldap-settings-encryption-key=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.H2Dialect"})
@AutoConfigureMockMvc
@ActiveProfiles("test")
class LdapSettingsControllerTest {
    @Autowired MockMvc mvc;
    @Autowired ObjectMapper mapper;
    @Autowired SystemSettingRepository repository;
    @Autowired org.springframework.transaction.PlatformTransactionManager transactions;
    @Autowired com.iflytek.skillhub.service.LdapSettingsAppService settingsService;
    @Autowired com.iflytek.skillhub.auth.ldap.LdapSettingsService runtimeSettings;
    @MockBean NamespaceMemberRepository namespaceMembers;
    // These unrelated repositories contain PostgreSQL-specific timestamp JPQL.
    @MockBean com.iflytek.skillhub.infra.jpa.ReviewTaskJpaRepository reviewTasks;
    @MockBean com.iflytek.skillhub.infra.jpa.PromotionRequestJpaRepository promotionRequests;
    private UsernamePasswordAuthenticationToken auth(String role) {
        return new UsernamePasswordAuthenticationToken(new PlatformPrincipal("admin", "admin", "a@example.com", "", "local", Set.of(role)), null,
                List.of(new SimpleGrantedAuthority("ROLE_" + role)));
    }
    @Test void permissionsAndCsrf() throws Exception {
        for (String role : List.of("USER", "USER_ADMIN")) {
            mvc.perform(get("/api/v1/admin/auth/ldap").with(authentication(auth(role)))).andExpect(status().isForbidden());
            mvc.perform(put("/api/v1/admin/auth/ldap").with(authentication(auth(role))).with(csrf())
                    .contentType("application/json").content("{\"version\":-1,\"configuration\":{}}" )).andExpect(status().isForbidden());
            mvc.perform(post("/api/v1/admin/auth/ldap/test").with(authentication(auth(role))).with(csrf())
                    .contentType("application/json").content("{\"version\":-1,\"configuration\":{}}" )).andExpect(status().isForbidden());
        }
        mvc.perform(put("/api/v1/admin/auth/ldap").with(authentication(auth("SUPER_ADMIN"))).cookie(new jakarta.servlet.http.Cookie("SESSION", "test-session"))
                .contentType("application/json").content("{\"version\":-1,\"configuration\":{}}" )).andExpect(status().is4xxClientError());
    }
    @Test void encryptedPersistenceSecretRedactionStaleVersionAndBlankPasswordPreservation() throws Exception {
        repository.findBySettingKey("auth.ldap").ifPresent(repository::delete);
        String body = "{\"version\":-1,\"configuration\":{\"enabled\":false,\"bindPassword\":\"private-reader-secret\"}}";
        String response = mvc.perform(put("/api/v1/admin/auth/ldap").with(authentication(auth("SUPER_ADMIN"))).with(csrf())
                .contentType("application/json").content(body)).andExpect(status().isOk())
                .andExpect(jsonPath("$.data.passwordConfigured").value(true))
                .andExpect(jsonPath("$.data.configuration.bindPassword").doesNotExist()).andReturn().getResponse().getContentAsString();
        assertThat(response).doesNotContain("private-reader-secret");
        assertThat(repository.findBySettingKey("auth.ldap").orElseThrow().getValue().toString()).doesNotContain("private-reader-secret");
        long version = mapper.readTree(response).path("data").path("version").asLong();
        mvc.perform(put("/api/v1/admin/auth/ldap").with(authentication(auth("SUPER_ADMIN"))).with(csrf()).contentType("application/json").content(body))
                .andExpect(status().isConflict());
        mvc.perform(put("/api/v1/admin/auth/ldap").with(authentication(auth("SUPER_ADMIN"))).with(csrf()).contentType("application/json")
                .content("{\"version\":" + version + ",\"configuration\":{\"enabled\":false,\"bindPassword\":\"\"}}"))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data.passwordConfigured").value(true));
    }
    @Test void liveAvailabilityDisableAndIdentityLock() throws Exception {
        repository.findBySettingKey("auth.ldap").ifPresent(repository::delete);
        var configuration = new com.iflytek.skillhub.auth.ldap.LdapAuthProperties();
        configuration.setEnabled(true); configuration.setDirectoryId("corp");
        configuration.setUrl("ldaps://127.0.0.1:1"); configuration.setBaseDn("dc=example,dc=com");
        configuration.setBindDn("cn=reader,dc=example,dc=com");
        var json = mapper.createObjectNode();
        json.put("version", -1); json.set("configuration", mapper.valueToTree(configuration));
        ((com.fasterxml.jackson.databind.node.ObjectNode)json.get("configuration")).put("bindPassword", "test-secret");
        String response = mvc.perform(put("/api/v1/admin/auth/ldap").with(authentication(auth("SUPER_ADMIN"))).with(csrf())
                .contentType("application/json").content(json.toString())).andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        mvc.perform(get("/api/v1/auth/methods")).andExpect(status().isOk())
                .andExpect(jsonPath("$.data[?(@.provider == 'ldap')]").isNotEmpty());
        long version = mapper.readTree(response).path("data").path("version").asLong();
        json.put("version", version);
        ((com.fasterxml.jackson.databind.node.ObjectNode)json.get("configuration")).put("enabled", false);
        response = mvc.perform(put("/api/v1/admin/auth/ldap").with(authentication(auth("SUPER_ADMIN"))).with(csrf())
                .contentType("application/json").content(json.toString())).andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        mvc.perform(get("/api/v1/auth/methods")).andExpect(status().isOk())
                .andExpect(jsonPath("$.data[?(@.provider == 'ldap')]").isEmpty());
        mvc.perform(post("/api/v1/auth/direct/login").with(csrf()).contentType("application/json")
                .content("{\"provider\":\"ldap\",\"username\":\"alice\",\"password\":\"secret\"}"))
                .andExpect(status().isForbidden());
        json.put("version", mapper.readTree(response).path("data").path("version").asLong());
        ((com.fasterxml.jackson.databind.node.ObjectNode)json.get("configuration")).put("directoryId", "changed");
        mvc.perform(put("/api/v1/admin/auth/ldap").with(authentication(auth("SUPER_ADMIN"))).with(csrf())
                .contentType("application/json").content(json.toString())).andExpect(status().isConflict());
    }

    @Test void concurrentUpdatesCannotOverwriteEachOther() throws Exception {
        repository.findBySettingKey("auth.ldap").ifPresent(repository::delete);
        var initial = settingsService.save(new com.iflytek.skillhub.dto.LdapSettingsUpdateRequest(-1L,
                new com.iflytek.skillhub.auth.ldap.LdapAuthProperties()), "admin", new com.iflytek.skillhub.service.AuditRequestContext("127.0.0.1", "test"));
        var barrier = new java.util.concurrent.CyclicBarrier(2);
        java.util.concurrent.Callable<Boolean> update = () -> {
            try {
                new org.springframework.transaction.support.TransactionTemplate(transactions).execute(status -> {
                    repository.findBySettingKey("auth.ldap").orElseThrow();
                    try { barrier.await(5, java.util.concurrent.TimeUnit.SECONDS); } catch (Exception failure) { throw new RuntimeException(failure); }
                    var config = new com.iflytek.skillhub.auth.ldap.LdapAuthProperties();
                    config.setDirectoryId(java.util.UUID.randomUUID().toString());
                    settingsService.save(new com.iflytek.skillhub.dto.LdapSettingsUpdateRequest(initial.version(), config), "admin",
                            new com.iflytek.skillhub.service.AuditRequestContext("127.0.0.1", "test"));
                    return null;
                });
                return true;
            } catch (org.springframework.orm.ObjectOptimisticLockingFailureException conflict) { return false; }
        };
        try (var executor = java.util.concurrent.Executors.newFixedThreadPool(2)) {
            var first = executor.submit(update); var second = executor.submit(update);
            assertThat(java.util.List.of(first.get(10, java.util.concurrent.TimeUnit.SECONDS), second.get(10, java.util.concurrent.TimeUnit.SECONDS)))
                    .containsExactlyInAnyOrder(true, false);
        }
        assertThat(repository.findBySettingKey("auth.ldap").orElseThrow().getVersion()).isEqualTo(initial.version() + 1);
    }

    @Test void invalidEnabledConfigLeavesSavedSettingsUntouchedAndTestDoesNotPersist() throws Exception {
        repository.findBySettingKey("auth.ldap").ifPresent(repository::delete);
        mvc.perform(put("/api/v1/admin/auth/ldap").with(authentication(auth("SUPER_ADMIN"))).with(csrf())
                .contentType("application/json").content("{\"version\":-1,\"configuration\":{\"enabled\":true}}"))
                .andExpect(status().isBadRequest());
        mvc.perform(post("/api/v1/admin/auth/ldap/test").with(authentication(auth("SUPER_ADMIN"))).with(csrf())
                .contentType("application/json").content("{\"version\":-1,\"configuration\":{}}"))
                .andExpect(status().isBadRequest());
        assertThat(repository.findBySettingKey("auth.ldap")).isEmpty();
        assertThat(runtimeSettings.enabled()).isFalse();
    }

    @Test void administratorCanReplaceUnreadableSecretWithoutExposingIt() throws Exception {
        repository.findBySettingKey("auth.ldap").ifPresent(repository::delete);
        var config = new com.iflytek.skillhub.auth.ldap.LdapAuthProperties();
        var values = new java.util.HashMap<String, Object>(runtimeSettings.encode(config));
        values.put("encryptedBindPassword", "unreadable-old-ciphertext");
        var row = repository.saveAndFlush(new com.iflytek.skillhub.auth.settings.SystemSetting("auth.ldap", values));
        mvc.perform(get("/api/v1/admin/auth/ldap").with(authentication(auth("SUPER_ADMIN"))))
                .andExpect(status().isOk()).andExpect(jsonPath("$.data.passwordConfigured").value(true))
                .andExpect(jsonPath("$.data.configuration.bindPassword").doesNotExist());
        config.setBindPassword("replacement-secret");
        settingsService.save(new com.iflytek.skillhub.dto.LdapSettingsUpdateRequest(row.getVersion(), config), "admin",
                new com.iflytek.skillhub.service.AuditRequestContext("127.0.0.1", "test"));
        assertThat(runtimeSettings.current().getBindPassword()).isEqualTo("replacement-secret");
    }

    @Test void exportsActualBackendContract() throws Exception {
        String schema = mvc.perform(get("/v3/api-docs")).andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        assertThat(schema).contains("/api/v1/admin/auth/ldap");
        java.nio.file.Files.writeString(java.nio.file.Path.of("target/ldap-settings-openapi.json"), schema);
    }
}
