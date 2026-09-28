package com.github.xingjianluo.sessionauthaccesscontroljava.security;

/** 登录 / 续期成功后下发的凭证对。 */
public record TokenPair(String accessToken, String refreshToken) {
}
