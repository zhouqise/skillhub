package com.iflytek.skillhub.auth.ldap;

import com.iflytek.skillhub.auth.exception.AuthFlowException;
import com.iflytek.skillhub.auth.federation.adapter.RemoteIdentityIoExecutor;
import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.sdk.Modification;
import com.unboundid.ldap.sdk.ModificationType;
import java.net.InetAddress;
import java.util.function.Supplier;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.ldap.core.support.LdapContextSource;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class LdapDirectoryAuthenticatorTest {
    private static final String USER_DN = "uid=alice,ou=nested,ou=people,dc=example,dc=com";
    private static final String ID = "550e8400-e29b-41d4-a716-446655440000";
    private InMemoryDirectoryServer server;
    private LdapAuthProperties properties;
    private int remoteCalls;

    @BeforeEach
    void startDirectory() throws Exception {
        InMemoryDirectoryServerConfig config = new InMemoryDirectoryServerConfig("dc=example,dc=com");
        config.setSchema(null);
        config.setGenerateOperationalAttributes(false);
        config.addAdditionalBindCredentials("cn=reader,dc=example,dc=com", "reader-secret");
        config.setListenerConfigs(InMemoryListenerConfig.createLDAPConfig("test", InetAddress.getLoopbackAddress(), 0, null));
        server = new InMemoryDirectoryServer(config);
        server.startListening();
        server.add("dn: dc=example,dc=com", "objectClass: domain", "dc: example");
        server.add("dn: ou=people,dc=example,dc=com", "objectClass: organizationalUnit", "ou: people");
        server.add("dn: ou=nested,ou=people,dc=example,dc=com", "objectClass: organizationalUnit", "ou: nested");
        server.add("dn: " + USER_DN, "objectClass: inetOrgPerson", "uid: alice", "cn: Alice", "sn: Test",
                "entryUUID: " + ID, "userPassword: user-secret");
        properties = properties(server.getListenPort());
    }

    @AfterEach
    void stopDirectory() {
        if (server != null) {
            server.shutDown(true);
        }
    }

    static LdapAuthProperties properties(int port) {
        LdapAuthProperties p = new LdapAuthProperties();
        p.setEnabled(true);
        p.setDirectoryId("corp");
        p.setUrl("ldap://127.0.0.1:" + port);
        p.setTlsMode("PLAIN");
        p.setBaseDn("dc=example,dc=com");
        p.setBindDn("cn=reader,dc=example,dc=com");
        p.setBindPassword("reader-secret");
        p.setUserSearchBase("ou=people");
        return p;
    }

    private LdapDirectoryAuthenticator authenticator() throws Exception {
        LdapContextSource source = new LdapAuthenticationConfiguration().ldapAuthContextSource(properties);
        source.afterPropertiesSet();
        return new LdapDirectoryAuthenticator(source, properties, new RemoteIdentityIoExecutor() {
            @Override
            public <T> T execute(Supplier<T> operation) {
                remoteCalls++;
                return operation.get();
            }
        });
    }

    @Test
    void authenticatesNestedOuAndKeepsIdentityAcrossRename() throws Exception {
        LdapDirectoryAuthenticator auth = authenticator();
        LdapIdentity before = auth.authenticate("alice", "user-secret");
        assertThat(before.subject()).isEqualTo("corp:entryuuid:" + ID);
        assertThat(before.displayName()).isEqualTo("Alice");
        server.modifyDN(USER_DN, "uid=renamed", true);
        assertThat(auth.authenticate("renamed", "user-secret").subject()).isEqualTo(before.subject());
        assertThat(remoteCalls).isEqualTo(2);
    }

    @Test
    void wrongPasswordUnknownUserAndFilterInjectionAreRejected() throws Exception {
        LdapDirectoryAuthenticator auth = authenticator();
        assertStatus(() -> auth.authenticate("alice", "wrong"), HttpStatus.UNAUTHORIZED);
        assertStatus(() -> auth.authenticate("missing", "user-secret"), HttpStatus.UNAUTHORIZED);
        assertStatus(() -> auth.authenticate("*)(uid=*)", "user-secret"), HttpStatus.UNAUTHORIZED);
    }

    @Test
    void emptyPasswordIsRejectedBeforeNetworkAndPasswordIsNotTrimmed() throws Exception {
        LdapDirectoryAuthenticator auth = authenticator();
        assertStatus(() -> auth.authenticate("alice", ""), HttpStatus.BAD_REQUEST);
        assertThat(remoteCalls).isZero();
        assertStatus(() -> auth.authenticate("alice", " user-secret "), HttpStatus.UNAUTHORIZED);
    }

    @Test
    void duplicateUsersAcrossSubtreesCannotSelectFirstResult() throws Exception {
        server.add("dn: uid=other,ou=people,dc=example,dc=com", "objectClass: inetOrgPerson", "uid: alice",
                "cn: Other", "sn: Test", "userPassword: user-secret", "entryUUID: 650e8400-e29b-41d4-a716-446655440000");
        LdapDirectoryAuthenticator auth = authenticator();
        assertStatus(() -> auth.authenticate("alice", "user-secret"), HttpStatus.UNAUTHORIZED);
    }

    @Test
    void missingStableIdentityIsAnOperationalFailure() throws Exception {
        server.modify(USER_DN, new Modification(ModificationType.DELETE, "entryUUID"));
        LdapDirectoryAuthenticator auth = authenticator();
        assertStatus(() -> auth.authenticate("alice", "user-secret"), HttpStatus.SERVICE_UNAVAILABLE);
    }

    @Test
    void badSearchCredentialDoesNotCountAsBadUserPassword() throws Exception {
        properties.setBindPassword("wrong-reader-secret");
        LdapDirectoryAuthenticator auth = authenticator();
        assertStatus(() -> auth.authenticate("alice", "user-secret"), HttpStatus.SERVICE_UNAVAILABLE);
    }

    @Test
    void binaryAdIdentifierIsStableAndSeparatedByDirectory() throws Exception {
        byte[] guid = new byte[16];
        guid[15] = 1;
        server.modify(USER_DN, new Modification(ModificationType.ADD, "objectGUID", guid));
        properties.setSubjectAttribute("objectGUID");
        assertThat(authenticator().authenticate("alice", "user-secret").subject())
                .isEqualTo("corp:objectguid:00000000000000000000000000000001");
        properties.setDirectoryId("other");
        assertThat(authenticator().authenticate("alice", "user-secret").subject()).startsWith("other:");
    }

    @Test
    void unavailableServerReturnsSafeError() throws Exception {
        LdapDirectoryAuthenticator auth = authenticator();
        server.shutDown(true);
        assertStatus(() -> auth.authenticate("alice", "user-secret"), HttpStatus.SERVICE_UNAVAILABLE);
    }

    @Test
    void secureModeCannotSilentlyUsePlainLdap() {
        properties.setTlsMode("LDAPS");
        assertThatThrownBy(properties::validate).isInstanceOf(IllegalArgumentException.class)
                .hasMessageNotContaining("reader-secret");
        properties.setEnabled(false);
        properties.validate();
    }

    private static void assertStatus(Runnable call, HttpStatus status) {
        assertThatThrownBy(call::run).isInstanceOfSatisfying(AuthFlowException.class, exception -> {
            assertThat(exception.getStatus()).isEqualTo(status);
            assertThat(exception.getMessage()).doesNotContain("user-secret", "reader-secret", "dc=example");
        });
    }
}
