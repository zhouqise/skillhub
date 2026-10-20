package com.iflytek.skillhub.auth.ldap;

import com.iflytek.skillhub.auth.exception.AuthFlowException;
import com.iflytek.skillhub.auth.federation.adapter.RemoteIdentityIoExecutor;
import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;
import com.unboundid.util.ssl.KeyStoreKeyManager;
import com.unboundid.util.ssl.SSLUtil;
import com.unboundid.util.ssl.TrustStoreTrustManager;
import java.net.InetAddress;
import java.util.function.Supplier;
import javax.net.ssl.SSLContext;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.springframework.http.HttpStatus;
import org.springframework.ldap.core.support.LdapContextSource;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@ResourceLock("JVM_SSL_CONTEXT")
class LdapTlsTest {
    @ParameterizedTest
    @ValueSource(strings = {"LDAPS", "STARTTLS"})
    void requiresTrustedCertificateAndAuthenticatesOverTls(String mode) throws Exception {
        Path certificate = Files.createTempDirectory("skillhub-ldap-tls").resolve("server.jks");
        Process keytool = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "keytool").toString(),
                "-genkeypair", "-alias", "ldap-test", "-keyalg", "RSA", "-keystore", certificate.toString(),
                "-storetype", "JKS", "-storepass", "test-secret", "-keypass", "test-secret", "-dname", "CN=localhost",
                "-ext", "SAN=ip:127.0.0.1,dns:localhost", "-validity", "1", "-noprompt")
                .redirectErrorStream(true).redirectOutput(ProcessBuilder.Redirect.DISCARD).start();
        assertThat(keytool.waitFor(30, TimeUnit.SECONDS)).isTrue();
        assertThat(keytool.exitValue()).isZero();
        SSLContext previous = SSLContext.getDefault();
        var keyManager = new KeyStoreKeyManager(certificate.toFile(), "test-secret".toCharArray(), "JKS", null);
        var trustManager = new TrustStoreTrustManager(certificate.toFile(), "test-secret".toCharArray(), "JKS", true);
        SSLUtil ssl = new SSLUtil(keyManager, trustManager);
        var config = new InMemoryDirectoryServerConfig("dc=example,dc=com");
        config.setSchema(null);
        config.setGenerateOperationalAttributes(false);
        config.addAdditionalBindCredentials("cn=reader,dc=example,dc=com", "reader-secret");
        config.setListenerConfigs("LDAPS".equals(mode)
                ? InMemoryListenerConfig.createLDAPSConfig("tls", InetAddress.getLoopbackAddress(), 0,
                    ssl.createSSLServerSocketFactory(), ssl.createSSLSocketFactory())
                : InMemoryListenerConfig.createLDAPConfig("tls", InetAddress.getLoopbackAddress(), 0, ssl.createSSLSocketFactory()));
        InMemoryDirectoryServer server = new InMemoryDirectoryServer(config);
        try {
            server.startListening();
            server.add("dn: dc=example,dc=com", "objectClass: domain", "dc: example");
            server.add("dn: ou=people,dc=example,dc=com", "objectClass: organizationalUnit", "ou: people");
            server.add("dn: uid=alice,ou=people,dc=example,dc=com", "objectClass: inetOrgPerson", "uid: alice",
                    "cn: Alice", "sn: Test", "entryUUID: 550e8400-e29b-41d4-a716-446655440000", "userPassword: user-secret");
            LdapAuthProperties p = LdapDirectoryAuthenticatorTest.properties(server.getListenPort());
            p.setTlsMode(mode);
            p.setUrl(("LDAPS".equals(mode) ? "ldaps" : "ldap") + "://127.0.0.1:" + server.getListenPort());
            assertThatThrownBy(() -> authenticator(p).authenticate("alice", "user-secret"))
                    .isInstanceOfSatisfying(AuthFlowException.class, ex -> assertThat(ex.getStatus()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE));
            SSLContext.setDefault(ssl.createSSLContext());
            assertThat(authenticator(p).authenticate("alice", "user-secret").subject())
                    .isEqualTo("corp:entryuuid:550e8400-e29b-41d4-a716-446655440000");
        } finally {
            SSLContext.setDefault(previous);
            server.shutDown(true);
            Files.deleteIfExists(certificate);
            Files.deleteIfExists(certificate.getParent());
        }
    }

    private static LdapDirectoryAuthenticator authenticator(LdapAuthProperties p) throws Exception {
        LdapContextSource source = new LdapAuthenticationConfiguration().ldapAuthContextSource(p);
        source.afterPropertiesSet();
        return new LdapDirectoryAuthenticator(source, p, new RemoteIdentityIoExecutor() {
            @Override
            public <T> T execute(Supplier<T> operation) { return operation.get(); }
        });
    }
}
