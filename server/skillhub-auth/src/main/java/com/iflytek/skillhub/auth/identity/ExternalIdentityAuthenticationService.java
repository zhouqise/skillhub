package com.iflytek.skillhub.auth.identity;

import com.iflytek.skillhub.auth.federation.core.IdentityCoreMode;
import com.iflytek.skillhub.auth.federation.core.IdentityLoginResolution;
import com.iflytek.skillhub.auth.oauth.AccountPendingException;
import com.iflytek.skillhub.auth.oauth.LegacyPlatformIdentityCore;
import com.iflytek.skillhub.auth.oauth.LegacyPlatformIdentityDecision;
import com.iflytek.skillhub.auth.oauth.OAuthClaims;
import com.iflytek.skillhub.auth.oauth.OAuthIdentityCoreException;
import com.iflytek.skillhub.auth.policy.AccessDecision;
import com.iflytek.skillhub.auth.policy.AccessPolicy;
import com.iflytek.skillhub.auth.rbac.PlatformPrincipal;
import com.iflytek.skillhub.domain.user.UserStatus;
import java.util.Objects;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.stereotype.Service;

/**
 * 统一编排已验证的外部身份准入、身份核心检查和精确绑定。
 *
 * <p>调用方必须先验证凭证；本服务不访问目录、不建立会话。账号写入及并发重读
 * 由 IdentityBindingService 的独立事务负责，保持 OAuth 与 LDAP 的账号守卫一致。
 */
@Service
public class ExternalIdentityAuthenticationService {
    private final AccessPolicy accessPolicy;
    private final IdentityBindingService identityBindingService;
    private final LegacyPlatformIdentityCore legacyPlatformIdentityCore;

    public ExternalIdentityAuthenticationService(AccessPolicy accessPolicy,
            IdentityBindingService identityBindingService, LegacyPlatformIdentityCore legacyPlatformIdentityCore) {
        this.accessPolicy = accessPolicy;
        this.identityBindingService = identityBindingService;
        this.legacyPlatformIdentityCore = legacyPlatformIdentityCore;
    }

    /**
     * 对可信身份执行准入并返回允许交互登录的平台主体。
     *
     * @param claims 已完成上游认证的属性，邮箱权威由来源明确声明
     * @return 精确绑定或新开户的主体；拒绝时不建立会话
     * @throws OAuth2AuthenticationException 准入或账号状态拒绝
     */
    public PlatformPrincipal authenticate(OAuthClaims claims) {
        AccessDecision decision = accessPolicy.evaluate(claims);

        if (decision == AccessDecision.PENDING_APPROVAL) {
            LegacyPlatformIdentityDecision identityDecision = legacyPlatformIdentityCore.evaluate(claims);
            ensureActiveCoreAllowsPlatformLogin(identityDecision);
            identityBindingService.createPendingUserIfAbsent(claims);
            throw new AccountPendingException();
        }
        if (decision == AccessDecision.DENY) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error("access_denied", "Access denied by policy", null)
            );
        }

        LegacyPlatformIdentityDecision identityDecision = legacyPlatformIdentityCore.evaluate(claims);
        ensureActiveCoreAllowsPlatformLogin(identityDecision);
        return identityBindingService.bindOrCreate(claims, UserStatus.ACTIVE);
    }

    private static void ensureActiveCoreAllowsPlatformLogin(LegacyPlatformIdentityDecision decision) {
        Objects.requireNonNull(decision, "identity decision must not be null");
        if (decision.mode() != IdentityCoreMode.ACTIVE) {
            return;
        }
        IdentityLoginResolution resolution = decision.resolution()
                .orElseThrow(() -> new OAuthIdentityCoreException(
                        new IllegalStateException("ACTIVE mode requires a unified identity resolution")
                ));
        if (resolution instanceof IdentityLoginResolution.Matched matched
                && matched.target().userId().isPresent()) {
            return;
        }
        if (resolution instanceof IdentityLoginResolution.ProvisionNew) {
            return;
        }
        throw new OAuthIdentityCoreException(
                new IllegalStateException("Unified identity denied platform OAuth login")
        );
    }

}
