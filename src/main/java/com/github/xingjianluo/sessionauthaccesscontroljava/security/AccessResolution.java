package com.github.xingjianluo.sessionauthaccesscontroljava.security;

/** 访问凭证解析结果：成功携带身份，失败携带可区分原因。 */
public record AccessResolution(boolean valid, Principal principal, AccessInvalidReason reason) {

    public static AccessResolution ok(Principal principal) {
        return new AccessResolution(true, principal, null);
    }

    public static AccessResolution invalid(AccessInvalidReason reason) {
        return new AccessResolution(false, null, reason);
    }
}
