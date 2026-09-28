package com.github.xingjianluo.sessionauthaccesscontroljava.web;

/**
 * 业务异常：携带 HTTP 状态码、机器可读错误码与提示信息。
 * 未登录 / 凭证不足 / 越权 / 限流各有独立错误码，调用方可区分。
 */
public class ApiException extends RuntimeException {

    private final int status;
    private final String code;

    public ApiException(int status, String code, String message) {
        super(message);
        this.status = status;
        this.code = code;
    }

    public int getStatus() { return status; }
    public String getCode() { return code; }
}
