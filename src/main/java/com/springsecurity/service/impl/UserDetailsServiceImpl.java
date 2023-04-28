package com.springsecurity.service.impl;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.springsecurity.entity.LoginUser;
import com.springsecurity.entity.User;
import com.springsecurity.mapper.MenuMapper;
import com.springsecurity.mapper.UserMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 *   与数据库进行操作
 */
@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    @Autowired
    private UserMapper userMapper;

    @Autowired
    private MenuMapper menuMapper;

//   可以观看之前粉色的那张图片，这个方法是由DaoAuthenticationProvider调用
//   我们要在这方法中做的就是 想数据库中查询，获取用户信息、查询权限信息
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
//      TODO 查询用户信息
        LambdaQueryWrapper<User> queryWrapper = new LambdaQueryWrapper<>();
        queryWrapper.eq(User::getUserName,username);

        User user = userMapper.selectOne(queryWrapper);
//      如果没有查询到用户，就抛出异常
        if(Objects.isNull(user)){
            throw new RuntimeException("用户不存在");
        }

//      TODO 查询对应的权限信息（讲到授权后在补全这个地方）
        List<String> list = menuMapper.selectPermsByUserId(user.getId());
//        List<String> list = new ArrayList<>(Arrays.asList("test","admin"));  //写死


//      TODO 封装成UserDetails将其返回
//      LoginUser是我们自己封装的一个UserDetails接口的实现类
        return new LoginUser(user,list);  //传入用户信息及权限集合
    }
}
