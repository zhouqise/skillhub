package com.iflytek.skillhub.controller;

import static org.assertj.core.api.Assertions.assertThat;

import com.iflytek.skillhub.auth.rbac.PlatformPrincipal;
import com.iflytek.skillhub.auth.session.PlatformSessionService;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.StringRedisSerializer;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;
import org.springframework.session.data.redis.RedisIndexedSessionRepository;
import org.springframework.session.web.http.SessionRepositoryFilter;

/**
 * Verifies the shared LDAP principal and security context survive a real Redis-backed HTTP session.
 * Opt in with an isolated local Redis port; never uses deployment connection settings.
 */
@EnabledIfEnvironmentVariable(named = "SKILLHUB_TEST_REDIS_PORT", matches = "[0-9]+")
class LdapRedisSessionTest {
    @Test
    void ldapPrincipalRoundTripsThroughRedisAndSessionCookie() throws Exception {
        LettuceConnectionFactory connection = new LettuceConnectionFactory("127.0.0.1",
                Integer.parseInt(System.getenv("SKILLHUB_TEST_REDIS_PORT")));
        connection.afterPropertiesSet();
        RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(connection);
        template.setKeySerializer(new StringRedisSerializer());
        template.setHashKeySerializer(new StringRedisSerializer());
        template.afterPropertiesSet();
        RedisIndexedSessionRepository repository = new RedisIndexedSessionRepository(template);
        repository.setRedisKeyNamespace("skillhub:test:ldap:" + UUID.randomUUID());
        repository.afterPropertiesSet();
        try {
            verifyHttpSession(repository);
        } finally {
            SecurityContextHolder.clearContext();
            repository.destroy();
            connection.destroy();
        }
    }

    private <S extends Session> void verifyHttpSession(SessionRepository<S> repository) throws Exception {
        SessionRepositoryFilter<S> filter = new SessionRepositoryFilter<>(repository);
        PlatformPrincipal principal = new PlatformPrincipal("ldap-test", "Directory User", null, null, "ldap", Set.of("USER"));
        MockHttpServletResponse firstResponse = new MockHttpServletResponse();
        AtomicReference<String> id = new AtomicReference<>();
        filter.doFilter(new MockHttpServletRequest(), firstResponse, (request, response) -> {
            HttpServletRequest http = (HttpServletRequest) request;
            String anonymousId = http.getSession().getId();
            new PlatformSessionService().establishSession(principal, http);
            id.set(http.getSession().getId());
            assertThat(id.get()).isNotEqualTo(anonymousId);
        });
        try {
            MockHttpServletRequest returning = new MockHttpServletRequest();
            returning.setCookies(firstResponse.getCookies());
            filter.doFilter(returning, new MockHttpServletResponse(), (request, response) -> {
                var session = ((HttpServletRequest) request).getSession(false);
                assertThat(session).isNotNull();
                assertThat(session.getAttribute("platformPrincipal")).isEqualTo(principal);
                SecurityContext context = (SecurityContext) session.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
                assertThat(context.getAuthentication().getPrincipal()).isEqualTo(principal);
                assertThat(context.getAuthentication().getCredentials()).isNull();
            });
        } finally {
            repository.deleteById(id.get());
        }
    }
}
