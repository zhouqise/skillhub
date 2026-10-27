package com.iflytek.skillhub.auth.ldap;

/**
 * 目录认证完成后的身份及展示资料，不含密码、DN 或权限声明。
 *
 * @param subject 目录空间、稳定属性类型与值组成的持久坐标
 * @param displayName 限长的目录展示名称
 * @param email 可空的目录邮箱，仅作资料展示，不声明邮箱已验证
 */
public record LdapIdentity(String subject, String displayName, String email) {
    public LdapIdentity(String subject, String displayName) { this(subject, displayName, null); }
}
