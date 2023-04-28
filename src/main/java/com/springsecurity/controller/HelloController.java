package com.springsecurity.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/hello")
public class HelloController {

    @GetMapping("/hello")
//    会执行hasAuthority('test')方法，返回值类型是布尔类型，如果是true就可以访问这个请求
    @PreAuthorize("hasAuthority('system:dept:list')")  //访问资源之前进行一个资源的认证，是否能够访问这个资源
    private String hello(){
        return "hello";
    }
}
