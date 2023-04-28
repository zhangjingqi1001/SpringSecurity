package com.springsecurity.handler;

import com.alibaba.fastjson.JSON;
import com.springsecurity.utils.ResponseResult;
import com.springsecurity.utils.WebUtils;
import org.apache.coyote.Response;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class AuthenticationEntryPointImpl implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        ResponseResult  r = new ResponseResult(HttpStatus.UNAUTHORIZED.value(),"用户认证失败。请重新登录");  //认证失败
        String json = JSON.toJSONString(r);
//      不论成功还是失败，都是JSON格式
        WebUtils.renderString(response,json);
    }
}
