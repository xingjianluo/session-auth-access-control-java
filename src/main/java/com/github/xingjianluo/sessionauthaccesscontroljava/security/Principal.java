package com.github.xingjianluo.sessionauthaccesscontroljava.security;

import com.github.xingjianluo.sessionauthaccesscontroljava.user.Role;

import java.util.Set;

/** 从访问凭证与用户目录解析出的当前请求身份。角色每次实时读取。 */
public record Principal(String username, String sessionId, Set<Role> roles) {
}
