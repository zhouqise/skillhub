package com.iflytek.skillhub.auth.ldap;

import com.iflytek.skillhub.auth.exception.AuthFlowException;
import com.iflytek.skillhub.auth.federation.adapter.RemoteIdentityIoExecutor;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.SizeLimitExceededException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapName;
import org.springframework.http.HttpStatus;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.ldap.support.LdapEncoder;

/**
 * 只读目录认证边界：先唯一搜索，再以用户凭证绑定并读取可信稳定属性。
 *
 * <p>所有网络访问暂停调用方事务，失败不写平台数据。搜索账号故障与用户密码错误
 * 分阶段分类；不跟随引用、不接受部分结果、不反序列化目录对象，并始终关闭上下文。
 */
public class LdapDirectoryAuthenticator {
    private final java.util.function.Supplier<LdapAuthProperties> settings;
    private final LdapContextSource ldapContextSource;
    private final LdapAuthProperties ldapAuthProperties;
    private final RemoteIdentityIoExecutor remoteIdentityIoExecutor;

    public LdapDirectoryAuthenticator(LdapContextSource ldapContextSource,
            LdapAuthProperties ldapAuthProperties, RemoteIdentityIoExecutor remoteIdentityIoExecutor) {
        this.settings = null;
        this.ldapContextSource = ldapContextSource;
        this.ldapAuthProperties = ldapAuthProperties;
        this.remoteIdentityIoExecutor = remoteIdentityIoExecutor;
    }

    public LdapDirectoryAuthenticator(java.util.function.Supplier<LdapAuthProperties> settings,
            RemoteIdentityIoExecutor remoteIdentityIoExecutor) {
        this.settings = settings;
        this.ldapContextSource = null;
        this.ldapAuthProperties = null;
        this.remoteIdentityIoExecutor = remoteIdentityIoExecutor;
    }

    /**
     * 完成本次目录认证，不缓存或存储用户密码。
     *
     * @param username 用户输入，去除两端空白后参与转义查询
     * @param password 原始密码，绝不 trim；空密码禁止进入匿名绑定
     * @return 从用户认证上下文读取的目录身份
     * @throws AuthFlowException 400 参数非法、401 凭证不可用、503 目录故障
     */
    public LdapIdentity authenticate(String username, String password) {
        if (settings != null) {
            LdapAuthProperties snapshot;
            try { snapshot = settings.get(); }
            catch (RuntimeException unavailable) {
                throw new AuthFlowException(HttpStatus.SERVICE_UNAVAILABLE, "error.auth.ldap.unavailable");
            }
            if (!snapshot.isEnabled()) throw new AuthFlowException(HttpStatus.FORBIDDEN, "error.auth.direct.disabled");
            try {
                snapshot.validate();
                LdapContextSource source = LdapAuthenticationConfiguration.createContextSource(snapshot);
                source.afterPropertiesSet();
                return new LdapDirectoryAuthenticator(source, snapshot, remoteIdentityIoExecutor).authenticate(username, password);
            } catch (IllegalArgumentException invalid) {
                throw new AuthFlowException(HttpStatus.SERVICE_UNAVAILABLE, "error.auth.ldap.unavailable");
            }
        }
        if (username == null || username.isBlank() || username.trim().length() > 256
                || password == null || password.isBlank() || password.length() > 4096) {
            throw new AuthFlowException(HttpStatus.BAD_REQUEST, "error.auth.ldap.invalidRequest");
        }
        return remoteIdentityIoExecutor.execute(() -> authenticateOutsideTransaction(username.trim(), password));
    }

    private LdapIdentity authenticateOutsideTransaction(String username, String password) {
        String fullDn = findUniqueDn(username);
        DirContext userContext = null;
        try {
            // 这里只将用户 bind 的认证失败归类为凭证错误；搜索账号失败在上一阶段返回 503。
            try {
                userContext = ldapContextSource.getContext(fullDn, password);
            } catch (org.springframework.ldap.AuthenticationException invalidCredentials) {
                throw credentials();
            }
            // 真实读取确保已完成认证，不仅以创建上下文成功作为身份凭据。
            List<String> requested = new ArrayList<>(List.of(ldapAuthProperties.getSubjectAttribute(),
                    ldapAuthProperties.getDisplayNameAttribute()));
            if (!ldapAuthProperties.getEmailAttribute().isEmpty()) requested.add(ldapAuthProperties.getEmailAttribute());
            Attributes attributes = userContext.getAttributes(fullDn, requested.toArray(String[]::new));
            String subject = stableSubject(attributes);
            Attribute name = attributes.get(ldapAuthProperties.getDisplayNameAttribute());
            String displayName = name != null && name.size() == 1 && name.get() instanceof String value
                    && !value.isBlank() ? value.trim() : subject;
            int end = displayName.offsetByCodePoints(0, Math.min(128, displayName.codePointCount(0, displayName.length())));
            return new LdapIdentity(subject, displayName.substring(0, end), directoryEmail(attributes));
        } catch (AuthFlowException classified) {
            throw classified;
        } catch (NamingException | org.springframework.ldap.NamingException failure) {
            throw unavailable();
        } finally {
            close(userContext);
        }
    }

    /** Optional directory contact data never participates in identity or authorization. */
    private String directoryEmail(Attributes attributes) throws NamingException {
        if (ldapAuthProperties.getEmailAttribute().isEmpty()) return null;
        Attribute mail = attributes.get(ldapAuthProperties.getEmailAttribute());
        if (mail == null || mail.size() != 1 || !(mail.get() instanceof String value)) return null;
        String email = value.trim();
        return email.length() <= 256 && email.matches("[^\\s@]+@[^\\s@]+\\.[^\\s@]+") ? email : null;
    }

    private String findUniqueDn(String username) {
        DirContext searchContext = null;
        NamingEnumeration<SearchResult> results = null;
        List<String> dns = new ArrayList<>(2);
        try {
            searchContext = ldapContextSource.getReadOnlyContext();
            SearchControls controls = new SearchControls();
            controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            controls.setCountLimit(2);
            controls.setTimeLimit(ldapAuthProperties.getSearchTimeLimitMs());
            controls.setReturningObjFlag(false);
            controls.setReturningAttributes(new String[] {"1.1"});
            String base = new LdapName(ldapAuthProperties.getBaseDn())
                    .addAll(new LdapName(ldapAuthProperties.getUserSearchBase())).toString();
            String filter = ldapAuthProperties.getUserFilter().replace("{0}", LdapEncoder.filterEncode(username));
            results = searchContext.search(base, filter, controls);
            while (results.hasMore()) {
                dns.add(results.next().getNameInNamespace());
                if (dns.size() == 2) {
                    throw credentials();
                }
            }
            if (dns.size() != 1) {
                throw credentials();
            }
            return dns.get(0);
        } catch (SizeLimitExceededException limited) {
            // 限制/超时之前取得一条并不能证明唯一，必须拒绝而非选择首条。
            throw dns.size() >= 2 ? credentials() : unavailable();
        } catch (AuthFlowException classified) {
            throw classified;
        } catch (NamingException | org.springframework.ldap.NamingException failure) {
            throw unavailable();
        } finally {
            if (results != null) {
                try {
                    results.close();
                } catch (NamingException ignored) {
                    // 连接随后关闭；不记录可能包含目录凭证或 DN 的异常详情。
                }
            }
            close(searchContext);
        }
    }

    private String stableSubject(Attributes attributes) throws NamingException {
        Attribute attribute = attributes.get(ldapAuthProperties.getSubjectAttribute());
        if (attribute == null || attribute.size() != 1) {
            throw unavailable();
        }
        Object value = attribute.get();
        if ("objectGUID".equals(ldapAuthProperties.getSubjectAttribute())) {
            if (!(value instanceof byte[] bytes) || bytes.length != 16) {
                throw unavailable();
            }
            return ldapAuthProperties.getDirectoryId() + ":objectguid:" + HexFormat.of().formatHex(bytes);
        }
        if (!(value instanceof String text) || !text.matches("(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")) {
            throw unavailable();
        }
        return ldapAuthProperties.getDirectoryId() + ":entryuuid:" + UUID.fromString(text);
    }

    private static AuthFlowException credentials() {
        return new AuthFlowException(HttpStatus.UNAUTHORIZED, "error.auth.ldap.credentials");
    }

    private static AuthFlowException unavailable() {
        return new AuthFlowException(HttpStatus.SERVICE_UNAVAILABLE, "error.auth.ldap.unavailable");
    }

    private static void close(DirContext context) {
        if (context != null) {
            try {
                context.close();
            } catch (NamingException ignored) {
                // 不改变已判定的认证结果，也不泄漏原始目录异常。
            }
        }
    }
}
