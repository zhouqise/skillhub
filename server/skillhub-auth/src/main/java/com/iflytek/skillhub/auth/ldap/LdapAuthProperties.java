package com.iflytek.skillhub.auth.ldap;

import java.net.URI;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * LDAP 目录的部署配置；仅在启用时验证，不保存用户登录凭证。
 *
 * <p>目录 ID 和稳定属性组成持久身份，不可在已有绑定后随意修改。
 * 搜索账号秘密没有 toString 表达，异常不得拼接属性值。
 */
@ConfigurationProperties(prefix = "skillhub.auth.ldap")
public class LdapAuthProperties {
    private boolean enabled = false;
    private String directoryId = "";
    private String url = "";
    private String tlsMode = "LDAPS";
    private String baseDn = "";
    private String bindDn = "";
    private String bindPassword = "";
    private String userSearchBase = "";
    private String userFilter = "(uid={0})";
    private String subjectAttribute = "entryUUID";
    private String displayNameAttribute = "cn";
    private int connectTimeoutMs = 3000;
    private int readTimeoutMs = 5000;
    private int searchTimeLimitMs = 5000;

    /**
     * 校验启用配置的结构，绝不在应用启动阶段连接目录。
     *
     * @throws IllegalArgumentException 配置非法；消息仅含字段类别，不含秘密
     */
    public void validate() {
        for (String value : new String[]{directoryId, url, tlsMode, baseDn, bindDn, userSearchBase,
                userFilter, subjectAttribute, displayNameAttribute}) {
            require(value != null && value.length() <= 2048, "field-length");
        }
        require(bindPassword != null && bindPassword.length() <= 4096, "bind-password");
        require(connectTimeoutMs > 0 && connectTimeoutMs <= 30000, "connect-timeout-ms");
        require(readTimeoutMs > 0 && readTimeoutMs <= 30000, "read-timeout-ms");
        require(searchTimeLimitMs > 0 && searchTimeLimitMs <= 30000, "search-time-limit-ms");
        if (!enabled) {
            return;
        }
        require(directoryId != null && directoryId.matches("[a-z0-9][a-z0-9_-]{0,31}"), "directory-id");
        require(url != null && !url.isBlank(), "url");
        URI uri;
        try {
            uri = URI.create(url);
        } catch (IllegalArgumentException invalid) {
            throw new IllegalArgumentException("Invalid LDAP url");
        }
        require(uri.getHost() != null && uri.getUserInfo() == null && uri.getQuery() == null
                && uri.getFragment() == null && (uri.getPath() == null || uri.getPath().isEmpty())
                && uri.getPort() >= -1 && uri.getPort() != 0 && uri.getPort() <= 65535, "url");
        require("LDAPS".equals(tlsMode) || "STARTTLS".equals(tlsMode) || "PLAIN".equals(tlsMode), "tls-mode");
        require("LDAPS".equals(tlsMode) ? "ldaps".equals(uri.getScheme()) : "ldap".equals(uri.getScheme()), "tls-mode/url");
        validateDn(baseDn, false);
        validateDn(bindDn, false);
        validateDn(userSearchBase, true);
        require(bindPassword != null && !bindPassword.isBlank(), "bind-password");
        require(userFilter != null && userFilter.contains("{0}")
                && !userFilter.replace("{0}", "").matches(".*[{}].*"), "user-filter");
        require("entryUUID".equals(subjectAttribute) || "objectGUID".equals(subjectAttribute), "subject-attribute");
        require(displayNameAttribute != null && displayNameAttribute.matches("[a-zA-Z][a-zA-Z0-9-]*"), "display-name-attribute");
        require(connectTimeoutMs > 0 && connectTimeoutMs <= 30000, "connect-timeout-ms");
        require(readTimeoutMs > 0 && readTimeoutMs <= 30000, "read-timeout-ms");
        require(searchTimeLimitMs > 0 && searchTimeLimitMs <= 30000, "search-time-limit-ms");
    }

    private static void validateDn(String value, boolean emptyAllowed) {
        require(value != null && (emptyAllowed || !value.isBlank()), "dn");
        try {
            new LdapName(value);
        } catch (InvalidNameException invalid) {
            throw new IllegalArgumentException("Invalid LDAP dn");
        }
    }

    private static void require(boolean valid, String field) {
        if (!valid) {
            throw new IllegalArgumentException("Invalid LDAP " + field);
        }
    }

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean value) { this.enabled = value; }
    public String getDirectoryId() { return directoryId; }
    public void setDirectoryId(String value) { this.directoryId = value; }
    public String getUrl() { return url; }
    public void setUrl(String value) { this.url = value; }
    public String getTlsMode() { return tlsMode; }
    public void setTlsMode(String value) { this.tlsMode = value; }
    public String getBaseDn() { return baseDn; }
    public void setBaseDn(String value) { this.baseDn = value; }
    public String getBindDn() { return bindDn; }
    public void setBindDn(String value) { this.bindDn = value; }
    @com.fasterxml.jackson.annotation.JsonProperty(access = com.fasterxml.jackson.annotation.JsonProperty.Access.WRITE_ONLY)
    public String getBindPassword() { return bindPassword; }
    public void setBindPassword(String value) { this.bindPassword = value; }
    public String getUserSearchBase() { return userSearchBase; }
    public void setUserSearchBase(String value) { this.userSearchBase = value; }
    public String getUserFilter() { return userFilter; }
    public void setUserFilter(String value) { this.userFilter = value; }
    public String getSubjectAttribute() { return subjectAttribute; }
    public void setSubjectAttribute(String value) { this.subjectAttribute = value; }
    public String getDisplayNameAttribute() { return displayNameAttribute; }
    public void setDisplayNameAttribute(String value) { this.displayNameAttribute = value; }
    public int getConnectTimeoutMs() { return connectTimeoutMs; }
    public void setConnectTimeoutMs(int value) { this.connectTimeoutMs = value; }
    public int getReadTimeoutMs() { return readTimeoutMs; }
    public void setReadTimeoutMs(int value) { this.readTimeoutMs = value; }
    public int getSearchTimeLimitMs() { return searchTimeLimitMs; }
    public void setSearchTimeLimitMs(int value) { this.searchTimeLimitMs = value; }
}
