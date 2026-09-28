package com.github.xingjianluo.sessionauthaccesscontroljava.web;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * 注册访问控制拦截器。
 *
 * <p>拦截器对全部 /api 路径生效；是否需要登录由方法/类上的
 * {@link com.github.xingjianluo.sessionauthaccesscontroljava.security.RequireRole}
 * 决定，未标注的接口（如登录、续期、公开 ping）按匿名访问放行。
 */
@Configuration
public class WebConfig implements WebMvcConfigurer {

    private final AuthInterceptor authInterceptor;

    public WebConfig(AuthInterceptor authInterceptor) {
        this.authInterceptor = authInterceptor;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(authInterceptor)
                .addPathPatterns("/api/**");
    }
}
