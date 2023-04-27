package com.springsecurity.service;

import com.springsecurity.entity.User;
import com.springsecurity.utils.ResponseResult;

public interface LoginService {
    ResponseResult login(User user);
}
