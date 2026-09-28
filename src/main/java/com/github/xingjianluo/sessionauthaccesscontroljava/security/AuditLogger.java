package com.github.xingjianluo.sessionauthaccesscontroljava.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.stereotype.Component;

/**
 * 审计日志：统一打印请求身份、命中的规则与最终结论。
 *
 * <p>输出形如：
 * {@code identity=alice rule=LOGIN decision=SUCCESS detail=...}，
 * 单测通过控制台日志即可观察每次判定走到了哪条规则、得到什么结论。
 * 使用 {@link MDC} 携带当前请求 id，便于并发场景下区分不同请求。
 */
@Component
public class AuditLogger {

    private static final Logger log = LoggerFactory.getLogger("AUTH-AUDIT");

    public void log(String identity, String rule, String decision) {
        log(identity, rule, decision, null);
    }

    public void log(String identity, String rule, String decision, String detail) {
        String requestId = MDC.get("requestId");
        StringBuilder sb = new StringBuilder("AUDIT ");
        sb.append("requestId=").append(requestId == null ? "-" : requestId);
        sb.append(" identity=").append(identity == null ? "anonymous" : identity);
        sb.append(" rule=").append(rule);
        sb.append(" decision=").append(decision);
        if (detail != null && !detail.isBlank()) {
            sb.append(" detail=").append(detail);
        }
        log.info(sb.toString());
    }
}
