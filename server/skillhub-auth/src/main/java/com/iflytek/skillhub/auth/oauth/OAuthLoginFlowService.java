package com.iflytek.skillhub.auth.oauth;

import com.iflytek.skillhub.auth.federation.adapter.RemoteIdentityIoExecutor;
import com.iflytek.skillhub.auth.identity.IdentityBindingService;
import com.iflytek.skillhub.auth.identity.ExternalIdentityAuthenticationService;
import com.iflytek.skillhub.auth.policy.AccessPolicy;
import com.iflytek.skillhub.auth.rbac.PlatformPrincipal;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

/**
 * Flow owner for browser OAuth login. It centralizes the stages of remembering
 * the return target, loading provider claims, evaluating access policy,
 * provisioning a platform principal, and resolving the final redirect target.
 */
@Service
public class OAuthLoginFlowService {

    private static final Logger log = LoggerFactory.getLogger(OAuthLoginFlowService.class);

    private final Map<String, OAuthClaimsExtractor> extractors;
    private final Map<String, ProviderOAuth2UserService> userServiceOverrides;
    private final ExternalIdentityAuthenticationService externalIdentityAuthenticationService;
    private final OAuth2UserService<OAuth2UserRequest, OAuth2User> delegate;
    private final RemoteIdentityIoExecutor remoteIdentityIo;

    @Autowired
    public OAuthLoginFlowService(List<OAuthClaimsExtractor> extractorList,
                                 List<ProviderOAuth2UserService> userServiceList,
                                 ExternalIdentityAuthenticationService externalIdentityAuthenticationService,
                                 RemoteIdentityIoExecutor remoteIdentityIo) {
        this(extractorList, userServiceList, externalIdentityAuthenticationService,
                new DefaultOAuth2UserService(), remoteIdentityIo);
    }

    OAuthLoginFlowService(List<OAuthClaimsExtractor> extractorList,
                          List<ProviderOAuth2UserService> userServiceList,
                          AccessPolicy accessPolicy,
                          IdentityBindingService identityBindingService,
                          LegacyPlatformIdentityCore identityCore,
                          OAuth2UserService<OAuth2UserRequest, OAuth2User> delegate,
                          RemoteIdentityIoExecutor remoteIdentityIo) {
        this(extractorList, userServiceList,
                new ExternalIdentityAuthenticationService(accessPolicy, identityBindingService, identityCore),
                delegate, remoteIdentityIo);
    }

    private OAuthLoginFlowService(List<OAuthClaimsExtractor> extractorList,
                                  List<ProviderOAuth2UserService> userServiceList,
                                  ExternalIdentityAuthenticationService externalIdentityAuthenticationService,
                                  OAuth2UserService<OAuth2UserRequest, OAuth2User> delegate,
                                  RemoteIdentityIoExecutor remoteIdentityIo) {
        this.extractors = extractorList.stream()
                .collect(Collectors.toMap(OAuthClaimsExtractor::getProvider, Function.identity()));
        this.userServiceOverrides = userServiceList.stream()
                .collect(Collectors.toMap(ProviderOAuth2UserService::getProvider, Function.identity()));
        this.externalIdentityAuthenticationService = externalIdentityAuthenticationService;
        this.delegate = delegate;
        this.remoteIdentityIo = remoteIdentityIo;
    }

    OAuthLoginFlowService(List<OAuthClaimsExtractor> extractorList,
                          AccessPolicy accessPolicy,
                          IdentityBindingService identityBindingService,
                          LegacyPlatformIdentityCore identityCore) {
        this(
                extractorList,
                List.of(),
                accessPolicy,
                identityBindingService,
                identityCore,
                new DefaultOAuth2UserService(),
                directRemoteIdentityIo()
        );
    }

    OAuthLoginFlowService(List<OAuthClaimsExtractor> extractorList,
                          AccessPolicy accessPolicy,
                          IdentityBindingService identityBindingService) {
        this(extractorList, accessPolicy, identityBindingService, ignored -> LegacyPlatformIdentityDecision.legacy());
    }

    public AuthenticatedLoginContext loadLoginContext(OAuth2UserRequest request) {
        LoadedProviderIdentity loadedIdentity = remoteIdentityIo.execute(() -> {
            String registrationId = request.getClientRegistration().getRegistrationId();
            ProviderOAuth2UserService override = userServiceOverrides.get(registrationId);
            OAuth2User upstreamUser = (override != null ? override : delegate).loadUser(request);
            OAuthClaimsExtractor extractor = extractors.get(registrationId);
            if (extractor == null) {
                throw new OAuth2AuthenticationException(
                        new OAuth2Error("unsupported_provider", "Unsupported: " + registrationId, null)
                );
            }
            OAuthClaims claims = extractor.extract(request, upstreamUser);
            log.info("OAuth provider identity loaded: provider={}, subjectPresent={}, emailPresent={}, displayNamePresent={}",
                    registrationId,
                    claims.subject() != null && !claims.subject().isBlank(),
                    claims.email() != null && !claims.email().isBlank(),
                    claims.providerLogin() != null && !claims.providerLogin().isBlank());
            return new LoadedProviderIdentity(upstreamUser, claims);
        });

        PlatformPrincipal principal = authenticate(loadedIdentity.claims());
        log.info("OAuth identity authenticated: provider={}, principalCreated=true, rolesCount={}",
                loadedIdentity.claims().provider(), principal.platformRoles().size());
        return new AuthenticatedLoginContext(loadedIdentity.upstreamUser(), principal);
    }

    /**
     * 将已验证的 OAuth/OIDC 属性交给共享平台身份编排。
     *
     * <p>保留原有异常契约；会话仍由成功回调建立。
     */
    public PlatformPrincipal authenticate(OAuthClaims claims) {
        return externalIdentityAuthenticationService.authenticate(claims);
    }

    public void rememberReturnTo(HttpServletRequest request) {
        String returnTo = OAuthLoginRedirectSupport.sanitizeReturnTo(request.getParameter("returnTo"));
        HttpSession session = request.getSession();
        if (returnTo == null) {
            session.removeAttribute(OAuthLoginRedirectSupport.SESSION_RETURN_TO_ATTRIBUTE);
            return;
        }
        session.setAttribute(OAuthLoginRedirectSupport.SESSION_RETURN_TO_ATTRIBUTE, returnTo);
    }

    public String consumeReturnTo(HttpSession session) {
        if (session == null) {
            return null;
        }
        Object value = session.getAttribute(OAuthLoginRedirectSupport.SESSION_RETURN_TO_ATTRIBUTE);
        session.removeAttribute(OAuthLoginRedirectSupport.SESSION_RETURN_TO_ATTRIBUTE);
        return value instanceof String str ? OAuthLoginRedirectSupport.sanitizeReturnTo(str) : null;
    }

    public String resolveFailureRedirect(AuthenticationException exception, String returnTo) {
        if (exception instanceof AccountPendingException) {
            return "/pending-approval";
        }
        if (exception instanceof AccountDisabledException
                || exception instanceof AccountMergedException
                || exception instanceof SystemAccountLoginException) {
            return "/access-denied";
        }
        if (exception instanceof OAuthIdentityCoreException) {
            return "/access-denied";
        }
        if (exception instanceof OAuth2AuthenticationException oauth2Exception
                && "access_denied".equals(oauth2Exception.getError().getErrorCode())) {
            return "/access-denied";
        }
        if (returnTo != null) {
            return "/login?returnTo=" + URLEncoder.encode(returnTo, StandardCharsets.UTF_8);
        }
        return null;
    }

    public record AuthenticatedLoginContext(OAuth2User upstreamUser, PlatformPrincipal principal) {
    }

    private record LoadedProviderIdentity(OAuth2User upstreamUser, OAuthClaims claims) {
    }

    private static RemoteIdentityIoExecutor directRemoteIdentityIo() {
        return new RemoteIdentityIoExecutor() {
            @Override
            public <T> T execute(java.util.function.Supplier<T> remoteIo) {
                return remoteIo.get();
            }
        };
    }
}
