package com.springsecurity.handler;

import com.alibaba.fastjson.JSON;
import com.springsecurity.utils.ResponseResult;
import com.springsecurity.utils.WebUtils;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class AccessDeniedHandlerImpl implements AccessDeniedHandler {
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        ResponseResult r = new ResponseResult(HttpStatus.FORBIDDEN.value(),"权限不足");  //认证失败
        String json = JSON.toJSONString(r);
//      不论成功还是失败，都是JSON格式
        WebUtils.renderString(response,json); // 封装的方法
    }
}
