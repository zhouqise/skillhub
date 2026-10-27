package com.iflytek.skillhub.auth.ldap;

import com.iflytek.skillhub.auth.direct.DirectAuthProvider;
import com.iflytek.skillhub.auth.direct.DirectAuthRequest;
import com.iflytek.skillhub.auth.exception.AuthFlowException;
import com.iflytek.skillhub.auth.identity.ExternalIdentityAuthenticationService;
import com.iflytek.skillhub.auth.oauth.OAuthClaims;
import com.iflytek.skillhub.auth.rbac.PlatformPrincipal;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;

/**
 * 将已验证的 LDAP 身份接入共享准入与开户链路，不自行写用户、角色或会话。
 *
 * <p>不声明邮箱权威，因而不会触发按已验证邮箱预授角色；目录失败不会回退本地认证。
 */
public class LdapDirectAuthProvider implements DirectAuthProvider {
    private final LdapDirectoryAuthenticator ldapDirectoryAuthenticator;
    private final ExternalIdentityAuthenticationService externalIdentityAuthenticationService;

    public LdapDirectAuthProvider(LdapDirectoryAuthenticator ldapDirectoryAuthenticator,
            ExternalIdentityAuthenticationService externalIdentityAuthenticationService) {
        this.ldapDirectoryAuthenticator = ldapDirectoryAuthenticator;
        this.externalIdentityAuthenticationService = externalIdentityAuthenticationService;
    }

    @Override
    public String providerCode() { return "ldap"; }

    @Override
    public String displayName() { return "LDAP"; }

    /**
     * 验证目录凭证后执行平台准入，返回可建立会话的主体。
     *
     * @param request 不可信的本次用户名密码，不作为平台角色或身份主键
     * @return 共享身份服务解析的平台主体
     * @throws AuthFlowException 凭证错误、目录不可用或平台拒绝；消息不含原始目录详情
     */
    @Override
    public PlatformPrincipal authenticate(DirectAuthRequest request) {
        LdapIdentity identity = ldapDirectoryAuthenticator.authenticate(request.username(), request.password());
        OAuthClaims claims = new OAuthClaims("ldap", identity.subject(), null, false,
                identity.displayName(), identity.email() == null ? Map.of() : Map.of("ldap_profile_email", identity.email()));
        try {
            PlatformPrincipal principal = externalIdentityAuthenticationService.authenticate(claims);
            // Directory contact data is displayed only in this LDAP session, never used for password recovery.
            return identity.email() == null ? principal : new PlatformPrincipal(principal.userId(),
                    principal.displayName(), identity.email(), principal.avatarUrl(), principal.oauthProvider(),
                    principal.platformRoles());
        } catch (OAuth2AuthenticationException denied) {
            throw new AuthFlowException(HttpStatus.FORBIDDEN, "error.auth.ldap.accessDenied");
        }
    }
}
