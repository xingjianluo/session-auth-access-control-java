package com.github.xingjianluo.sessionauthaccesscontroljava.security;

import com.github.xingjianluo.sessionauthaccesscontroljava.user.Role;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/** 标注接口所需角色，任意一个命中即放行。 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface RequireRole {
    Role[] value();
}
