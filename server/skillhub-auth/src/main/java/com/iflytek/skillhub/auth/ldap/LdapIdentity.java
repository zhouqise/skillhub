package com.iflytek.skillhub.auth.ldap;

/**
 * 目录认证完成后的内部身份结果，不含密码、DN、邮箱或权限声明。
 *
 * @param subject 目录空间、稳定属性类型与值组成的持久坐标
 * @param displayName 目录提供的展示名称，限制为平台允许的长度
 */
public record LdapIdentity(String subject, String displayName) {}
