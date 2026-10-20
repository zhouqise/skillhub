package com.iflytek.skillhub.auth.ldap;

import com.iflytek.skillhub.auth.direct.DirectAuthRequest;
import com.iflytek.skillhub.auth.exception.AuthFlowException;
import com.iflytek.skillhub.auth.identity.ExternalIdentityAuthenticationService;
import com.iflytek.skillhub.auth.oauth.AccountDisabledException;
import com.iflytek.skillhub.auth.oauth.OAuthClaims;
import com.iflytek.skillhub.auth.rbac.PlatformPrincipal;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.HttpStatus;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

class LdapDirectAuthProviderTest {
    private final LdapDirectoryAuthenticator directory = mock(LdapDirectoryAuthenticator.class);
    private final ExternalIdentityAuthenticationService identities = mock(ExternalIdentityAuthenticationService.class);
    private final LdapDirectAuthProvider provider = new LdapDirectAuthProvider(directory, identities);

    @Test
    void passesOnlyVerifiedDirectoryIdentityWithoutEmailAuthority() {
        when(directory.authenticate("alice", "secret")).thenReturn(new LdapIdentity("corp:entryuuid:abc", "Alice"));
        PlatformPrincipal expected = new PlatformPrincipal("usr_1", "Alice", null, null, "ldap", Set.of("USER"));
        when(identities.authenticate(any())).thenReturn(expected);
        assertThat(provider.authenticate(new DirectAuthRequest("alice", "secret"))).isSameAs(expected);
        ArgumentCaptor<OAuthClaims> claims = ArgumentCaptor.forClass(OAuthClaims.class);
        verify(identities).authenticate(claims.capture());
        assertThat(claims.getValue().provider()).isEqualTo("ldap");
        assertThat(claims.getValue().subject()).isEqualTo("corp:entryuuid:abc");
        assertThat(claims.getValue().email()).isNull();
        assertThat(claims.getValue().emailVerified()).isFalse();
    }

    @Test
    void directoryFailureCannotProvisionAnAccount() {
        when(directory.authenticate(any(), any())).thenThrow(new AuthFlowException(HttpStatus.UNAUTHORIZED, "error.auth.ldap.credentials"));
        assertThatThrownBy(() -> provider.authenticate(new DirectAuthRequest("alice", "wrong")))
            .isInstanceOf(AuthFlowException.class);
        verifyNoInteractions(identities);
    }

    @Test
    void disabledPlatformAccountBecomesForbiddenWithoutFallback() {
        when(directory.authenticate(any(), any())).thenReturn(new LdapIdentity("corp:entryuuid:abc", "Alice"));
        when(identities.authenticate(any())).thenThrow(new AccountDisabledException());
        assertThatThrownBy(() -> provider.authenticate(new DirectAuthRequest("alice", "secret")))
            .isInstanceOfSatisfying(AuthFlowException.class, ex -> assertThat(ex.getStatus()).isEqualTo(HttpStatus.FORBIDDEN));
    }
}
