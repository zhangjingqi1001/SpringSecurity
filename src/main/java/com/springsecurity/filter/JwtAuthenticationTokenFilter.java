package com.springsecurity.filter;

import com.springsecurity.entity.LoginUser;
import com.springsecurity.utils.JwtUtil;
import com.springsecurity.utils.RedisCache;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.lang.Objects;
import io.jsonwebtoken.lang.Strings;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 之前我们选择的是实现Filter接口，但是这个过滤器接口存在一点问题，有可能发一次请求经过好几次过滤器
 * OncePerRequestFilter  是过滤器的实现类，一次请求只经过一个过滤器
 */
@Component
public class JwtAuthenticationTokenFilter extends OncePerRequestFilter {
    @Autowired
    private RedisCache redisCache;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
//      TODO 获取token (前端发送请求携带过来)
        String token = request.getHeader("token");   //有可能是空的，不一定所有的请求都携带token
        if (!Strings.hasText(token)) {
//          说明token没有，直接放行
//          为什么放行？  因为后面的操作是对token的解析，而这个请求没有携带token
//                      除此之外，后面还有其他的过滤器，也可以在进行判断（比如说在FilterSecurityInterceptor中）
            filterChain.doFilter(request, response);
//          为什么加return？  放行后会执行到后面的几个过滤器，都执行完然后响应的时候还会执行一遍过滤器链
            return;
        }

//      TODO 解析token
        Claims claims = null;
        String userId =null;
        try {
            claims = JwtUtil.parseJWT(token);
//          这样获取的就是生成token的原来数据，因为当时我们使用userid生成的token
             userId = claims.getSubject();
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("token非法");
        }

//      TODO 从Redis中获取用户信息
        String redisKey = "login:"+userId;
        LoginUser loginUser = redisCache.getCacheObject(redisKey);
        if (loginUser ==null ){
            throw new RuntimeException("token非法");
        }


//      TODO 将用户信息存入到SecurityContextHolder中、获取权限信息封装到Authentication中
//      三个参数：在构造方法中会有一个super.setAuthenticated(true)，表示已认证的情况
//      第一个参数：用户信息，第二个参数：null,第三个参数：Collection集合，有关权限的信息，但是现在还没有权限信息，先写null
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(loginUser,null,loginUser.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);

//      TODO: 放行
        filterChain.doFilter(request, response);
    }
}
