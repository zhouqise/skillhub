package com.iflytek.skillhub.controller;

import static org.mockito.BDDMockito.given;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.iflytek.skillhub.auth.local.LocalCredentialRepository;
import com.iflytek.skillhub.auth.local.LocalAuthService;
import com.iflytek.skillhub.auth.settings.LocalAuthSettings;
import com.iflytek.skillhub.auth.settings.LocalAuthSettingsService;
import com.iflytek.skillhub.auth.repository.UserRoleBindingRepository;
import com.iflytek.skillhub.auth.rbac.PlatformPrincipal;
import com.iflytek.skillhub.domain.namespace.NamespaceMemberRepository;
import com.iflytek.skillhub.domain.user.UserAccount;
import com.iflytek.skillhub.domain.user.UserAccountRepository;
import com.iflytek.skillhub.security.AuthFailureThrottleService;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@TestPropertySource(properties = {
    "skillhub.auth.direct.enabled=true",
    "skillhub.auth.ldap.enabled=true",
    "skillhub.auth.ldap.directory-id=corp",
    "skillhub.auth.ldap.url=ldaps://localhost:1",
    "skillhub.auth.ldap.base-dn=dc=example,dc=com",
    "skillhub.auth.ldap.bind-dn=cn=reader,dc=example,dc=com",
    "skillhub.auth.ldap.bind-password=test-secret"
})
class LdapAuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private LocalAuthService localAuthService;

    @MockBean
    private com.iflytek.skillhub.auth.ldap.LdapDirectoryAuthenticator ldapDirectoryAuthenticator;

    @MockBean
    private com.iflytek.skillhub.auth.identity.ExternalIdentityAuthenticationService externalIdentityAuthenticationService;

    @MockBean
    private NamespaceMemberRepository namespaceMemberRepository;

    @MockBean
    private AuthFailureThrottleService authFailureThrottleService;

    @MockBean
    private UserAccountRepository userAccountRepository;

    @MockBean
    private UserRoleBindingRepository userRoleBindingRepository;

    @MockBean
    private LocalCredentialRepository localCredentialRepository;

    @MockBean
    private LocalAuthSettingsService localAuthSettingsService;

    @org.junit.jupiter.api.BeforeEach
    void localAuthEnabled() {
        given(localAuthSettingsService.current()).willReturn(new LocalAuthSettings(1L, true, true, 0L, null));
    }

    @Test
    void ldapLoginCreatesSessionWithoutLocalPasswordCapability() throws Exception {
        PlatformPrincipal principal = new PlatformPrincipal(
            "usr_direct_1",
            "direct-user",
            null,
            null,
            "ldap",
            Set.of("USER")
        );
        given(ldapDirectoryAuthenticator.authenticate("direct-user", "Abcd123!"))
            .willReturn(new com.iflytek.skillhub.auth.ldap.LdapIdentity("corp:entryuuid:550e8400-e29b-41d4-a716-446655440000", "direct-user"));
        given(externalIdentityAuthenticationService.authenticate(org.mockito.ArgumentMatchers.any())).willReturn(principal);
        given(namespaceMemberRepository.findByUserId("usr_direct_1")).willReturn(List.of());
        given(userAccountRepository.findById("usr_direct_1"))
            .willReturn(java.util.Optional.of(new UserAccount("usr_direct_1", "direct-user", null, null)));
        given(userRoleBindingRepository.findByUserId("usr_direct_1")).willReturn(List.of());
        given(localCredentialRepository.existsByUserId("usr_direct_1")).willReturn(false);

        MockHttpSession session = (MockHttpSession) mockMvc.perform(post("/api/v1/auth/direct/login")
                .with(csrf())
                .contentType("application/json")
                .content("""
                    {"provider":"ldap","username":"direct-user","password":"Abcd123!"}
                    """))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.code").value(0))
            .andExpect(jsonPath("$.data.userId").value("usr_direct_1"))
            .andExpect(jsonPath("$.data.canChangePassword").value(false))
            .andReturn()
            .getRequest()
            .getSession(false);

        mockMvc.perform(get("/api/v1/auth/me").session(session))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.code").value(0))
            .andExpect(jsonPath("$.data.userId").value("usr_direct_1"))
            .andExpect(jsonPath("$.data.canChangePassword").value(false));
    }

    @Test
    void ldapMethodIsDiscovered() throws Exception {
        mockMvc.perform(get("/api/v1/auth/methods"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.data[?(@.provider == 'ldap')].methodType").value(org.hamcrest.Matchers.hasItem("DIRECT_PASSWORD")));
    }

    @Test
    void ldapWrongPasswordUsesExistingFailureThrottle() throws Exception {
        given(ldapDirectoryAuthenticator.authenticate("alice", "wrong"))
            .willThrow(new com.iflytek.skillhub.auth.exception.AuthFlowException(
                org.springframework.http.HttpStatus.UNAUTHORIZED, "error.auth.ldap.credentials"));
        mockMvc.perform(post("/api/v1/auth/direct/login").with(csrf()).contentType("application/json")
                .content("{\"provider\":\"ldap\",\"username\":\"alice\",\"password\":\"wrong\"}"))
            .andExpect(status().isUnauthorized());
        org.mockito.Mockito.verifyNoInteractions(externalIdentityAuthenticationService);
        org.mockito.Mockito.verify(authFailureThrottleService).recordFailure(
            org.mockito.ArgumentMatchers.eq("direct:ldap"), org.mockito.ArgumentMatchers.eq("alice"), org.mockito.ArgumentMatchers.any());
    }

    @Test
    void directLoginShouldRejectUnsupportedProvider() throws Exception {
        mockMvc.perform(post("/api/v1/auth/direct/login")
                .with(csrf())
                .contentType("application/json")
                .content("""
                    {"provider":"private-sso","username":"user","password":"pw"}
                    """))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.code").value(400));
    }
}
