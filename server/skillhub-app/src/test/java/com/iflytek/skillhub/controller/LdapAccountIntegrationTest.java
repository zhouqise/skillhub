package com.iflytek.skillhub.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.BDDMockito.given;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.iflytek.skillhub.auth.direct.DirectAuthRequest;
import com.iflytek.skillhub.auth.ldap.LdapDirectoryAuthenticator;
import com.iflytek.skillhub.auth.ldap.LdapDirectAuthProvider;
import com.iflytek.skillhub.auth.ldap.LdapIdentity;
import com.iflytek.skillhub.auth.local.LocalCredentialRepository;
import com.iflytek.skillhub.auth.repository.IdentityBindingRepository;
import com.iflytek.skillhub.domain.namespace.GlobalNamespaceMembershipService;
import com.iflytek.skillhub.domain.user.UserAccount;
import com.iflytek.skillhub.domain.user.UserAccountRepository;
import com.iflytek.skillhub.domain.user.UserStatus;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Exercises LDAP's real platform policy, account transactions and HTTP session against the test DB.
 * Directory protocol is covered separately; directory I/O, local capability settings and namespace setup are mocked.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@TestPropertySource(properties = {
    "spring.jpa.properties.hibernate.dialect=org.hibernate.dialect.H2Dialect",
    "skillhub.auth.direct.enabled=true", "skillhub.auth.ldap.enabled=true",
    "skillhub.auth.ldap.directory-id=corp", "skillhub.auth.ldap.url=ldaps://localhost:1",
    "skillhub.auth.ldap.base-dn=dc=example,dc=com", "skillhub.auth.ldap.bind-dn=cn=reader,dc=example,dc=com",
    "skillhub.auth.ldap.bind-password=test-secret"
})
class LdapAccountIntegrationTest {
    @Autowired private MockMvc mvc;
    @Autowired private org.springframework.jdbc.core.JdbcTemplate jdbc;
    @Autowired private ObjectMapper mapper;
    @Autowired private UserAccountRepository users;
    @Autowired private IdentityBindingRepository bindings;
    @Autowired private com.iflytek.skillhub.auth.repository.UserRoleBindingRepository roleBindings;
    @Autowired private org.springframework.transaction.PlatformTransactionManager transactionManager;
    @Autowired private com.iflytek.skillhub.auth.settings.InitialExternalRoleGrantService initialRoleGrants;
    @Autowired private com.iflytek.skillhub.auth.policy.AccessPolicy accessPolicy;
    @Autowired private com.iflytek.skillhub.auth.oauth.LegacyPlatformIdentityCore identityCore;
    @Autowired private LocalCredentialRepository credentials;
    @Autowired private LdapDirectAuthProvider provider;
    // Unrelated PostgreSQL-specific review projections are not part of authentication coverage.
    @MockBean private com.iflytek.skillhub.infra.jpa.ReviewTaskJpaRepository reviewTasks;
    @MockBean private com.iflytek.skillhub.infra.jpa.PromotionRequestJpaRepository promotionRequests;
    @MockBean private LdapDirectoryAuthenticator directory;
    @MockBean private com.iflytek.skillhub.auth.settings.LocalAuthSettingsService localAuthSettingsService;

    @org.junit.jupiter.api.BeforeEach
    void localCapabilities() {
        given(localAuthSettingsService.current()).willReturn(
            new com.iflytek.skillhub.auth.settings.LocalAuthSettings(1L, true, true, 0L, null));
    }
    @MockBean private GlobalNamespaceMembershipService globalNamespaceMembershipService;

    @Test
    void firstLoginCreatesOrdinaryAccountWithoutMergingNameOrLocalPasswordAndRotatesSession() throws Exception {
        String name = "same-name-" + UUID.randomUUID();
        String localId = "local-" + UUID.randomUUID();
        users.save(new UserAccount(localId, name, "local@example.com", null));
        String subject = "corp:entryuuid:" + UUID.randomUUID();
        given(directory.authenticate(name, "secret")).willReturn(new LdapIdentity(subject, name, "local@example.com"));
        MockHttpSession session = new MockHttpSession();
        String before = session.getId();
        var result = mvc.perform(post("/api/v1/auth/direct/login").session(session).with(csrf())
                .contentType("application/json").content(mapper.writeValueAsString(
                    java.util.Map.of("provider", "ldap", "username", name, "password", "secret"))))
            .andExpect(status().isOk()).andReturn();
        String id = mapper.readTree(result.getResponse().getContentAsString()).path("data").path("userId").asText();
        assertThat(id).isNotBlank().isNotEqualTo(localId);
        assertThat(session.getId()).isNotEqualTo(before);
        assertThat(bindings.findByProviderCodeAndSubject("ldap", subject).orElseThrow().getUserId()).isEqualTo(id);
        assertThat(credentials.existsByUserId(id)).isFalse();
        assertThat(users.findById(id).orElseThrow().getEmail()).isNull();
        assertThat(users.findById(localId).orElseThrow().getEmail()).isEqualTo("local@example.com");
        assertThat(bindings.findByProviderCodeAndSubject("ldap", subject).orElseThrow().getExtraJson())
                .contains("local@example.com");
        assertThat(users.findById(id).orElseThrow().getStatus()).isEqualTo(UserStatus.ACTIVE);
        var returning = provider.authenticate(new DirectAuthRequest(name, "secret"));
        assertThat(returning.userId()).isEqualTo(id);
        assertThat(returning.platformRoles()).containsExactly("USER");
        assertThat(returning.email()).isEqualTo("local@example.com");
        given(directory.authenticate(name, "secret")).willReturn(new LdapIdentity(subject, name));
        assertThat(provider.authenticate(new DirectAuthRequest(name, "secret")).email()).isNull();
        assertThat(bindings.findByProviderCodeAndSubject("ldap", subject).orElseThrow().getExtraJson()).isEqualTo("{}");
        UserAccount disabled = users.findById(id).orElseThrow();
        disabled.setStatus(UserStatus.DISABLED);
        users.save(disabled);
        mvc.perform(post("/api/v1/auth/direct/login").with(csrf()).contentType("application/json")
                .content(mapper.writeValueAsString(java.util.Map.of("provider", "ldap", "username", name, "password", "secret"))))
            .andExpect(status().isForbidden());
    }

    @Test
    void concurrentFirstLoginResolvesOneOrdinaryAccount() throws Exception {
        String name = "concurrent-" + UUID.randomUUID();
        String subject = "corp:entryuuid:" + UUID.randomUUID();
        long usersBefore = jdbc.queryForObject("SELECT COUNT(*) FROM user_account", Long.class);
        long bindingsBefore = bindings.count();
        java.util.concurrent.CyclicBarrier absentBinding = new java.util.concurrent.CyclicBarrier(2);
        IdentityBindingRepository synchronizedBindings = org.mockito.Mockito.mock(IdentityBindingRepository.class,
                org.mockito.AdditionalAnswers.delegatesTo(bindings));
        org.mockito.Mockito.doAnswer(invocation -> {
            var result = bindings.findByProviderCodeAndSubject("ldap", subject);
            if (result.isEmpty()) {
                // Both transactions must observe no binding before either can insert.
                absentBinding.await(10, TimeUnit.SECONDS);
            }
            return result;
        }).when(synchronizedBindings).findByProviderCodeAndSubject("ldap", subject);
        var events = org.mockito.Mockito.mock(org.springframework.context.ApplicationEventPublisher.class);
        var bindingService = new com.iflytek.skillhub.auth.identity.IdentityBindingService(synchronizedBindings,
                users, roleBindings, globalNamespaceMembershipService, events, transactionManager, initialRoleGrants);
        var concurrentProvider = new LdapDirectAuthProvider(directory,
                new com.iflytek.skillhub.auth.identity.ExternalIdentityAuthenticationService(accessPolicy, bindingService, identityCore));
        given(directory.authenticate(name, "secret")).willReturn(new LdapIdentity(subject, name));
        try (var executor = Executors.newFixedThreadPool(2)) {
            java.util.concurrent.Callable<String> login = () -> {
                var principal = concurrentProvider.authenticate(new DirectAuthRequest(name, "secret"));
                assertThat(principal.platformRoles()).containsExactly("USER");
                return principal.userId();
            };
            var first = executor.submit(login);
            var second = executor.submit(login);
            assertThat(first.get(20, TimeUnit.SECONDS)).isEqualTo(second.get(20, TimeUnit.SECONDS));
            var binding = bindings.findByProviderCodeAndSubject("ldap", subject).orElseThrow();
            assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM user_account", Long.class)).isEqualTo(usersBefore + 1);
            assertThat(bindings.count()).isEqualTo(bindingsBefore + 1);
            org.mockito.Mockito.verify(events, org.mockito.Mockito.times(1)).publishEvent(
                    org.mockito.ArgumentMatchers.any(com.iflytek.skillhub.domain.event.UserActivatedEvent.class));
            org.mockito.Mockito.verify(globalNamespaceMembershipService, org.mockito.Mockito.times(1)).ensureMember(binding.getUserId());
            org.mockito.Mockito.verify(globalNamespaceMembershipService, org.mockito.Mockito.times(1)).ensureMember(org.mockito.ArgumentMatchers.anyString());
        }
    }
}
