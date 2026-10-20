package com.iflytek.skillhub.auth.ldap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.iflytek.skillhub.auth.exception.AuthFlowException;
import com.iflytek.skillhub.auth.federation.adapter.RemoteIdentityIoExecutor;
import java.util.function.Supplier;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.PartialResultException;
import javax.naming.SizeLimitExceededException;
import javax.naming.TimeLimitExceededException;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.HttpStatus;
import org.springframework.ldap.core.support.LdapContextSource;

class LdapSearchFailureTest {
    @ParameterizedTest
    @ValueSource(strings = {"size", "time", "referral"})
    void incompleteSingleResultIsNotAcceptedAndResourcesAreClosed(String failure) throws Exception {
        LdapContextSource source = mock(LdapContextSource.class);
        DirContext context = mock(DirContext.class);
        NamingException exception = switch (failure) {
            case "size" -> new SizeLimitExceededException();
            case "time" -> new TimeLimitExceededException();
            default -> new PartialResultException();
        };
        SearchResult entry = new SearchResult("uid=alice", null, null);
        entry.setNameInNamespace("uid=alice,dc=example,dc=com");
        class Results implements NamingEnumeration<SearchResult> {
            boolean consumed;
            boolean closed;
            public boolean hasMore() throws NamingException { if (consumed) throw exception; return true; }
            public SearchResult next() { consumed = true; return entry; }
            public void close() { closed = true; }
            public boolean hasMoreElements() { throw new AssertionError("Must use exception-aware hasMore"); }
            public SearchResult nextElement() { throw new AssertionError("Must use exception-aware next"); }
        }
        Results results = new Results();
        when(source.getReadOnlyContext()).thenReturn(context);
        when(context.search(anyString(), anyString(), any(SearchControls.class))).thenReturn(results);
        LdapDirectoryAuthenticator authenticator = new LdapDirectoryAuthenticator(source,
                LdapDirectoryAuthenticatorTest.properties(389), new RemoteIdentityIoExecutor() {
                    public <T> T execute(Supplier<T> operation) { return operation.get(); }
                });
        assertThatThrownBy(() -> authenticator.authenticate("alice", "secret"))
            .isInstanceOfSatisfying(AuthFlowException.class, ex -> assertThat(ex.getStatus()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE));
        verify(source, never()).getContext(anyString(), anyString());
        verify(context).close();
        assertThat(results.closed).isTrue();
    }
}
