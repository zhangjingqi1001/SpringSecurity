package com.springsecurity.service.impl;

import com.springsecurity.entity.LoginUser;
import com.springsecurity.entity.User;
import com.springsecurity.service.LoginService;
import com.springsecurity.utils.JwtUtil;
import com.springsecurity.utils.RedisCache;
import com.springsecurity.utils.ResponseResult;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

@Service
public class LoginServiceImpl implements LoginService {


    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private RedisCache redisCache;

    @Override
    public ResponseResult login(User user) {
//       TODO 通过AuthenticationManager的authenticate方法来进行用户认证
//          需要Authentication类型(接口)的参数,我们可以使用Authentication的实现类UsernamePasswordAuthenticationToken
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user.getUserName(), user.getPassword());
        Authentication authenticate = authenticationManager.authenticate(authenticationToken);

//      TODO  如果认证没通过，给出对应的提示
        if (Objects.isNull(authenticate)) {
            throw new RuntimeException("登录失败");
        }

//      TODO 如果认证通过了，使用userId生成一个jwt，封装成ResponseResult对象进行返回
//          这个地方为什么能强转成LoginUser类型？
//           UserDetailsServiceImpl类实现了UserDetailsService并且重写了loadUserByUsername方法，其方法返回值是UserDetails
//           但是创建了一个类LoginUser实现了UserDetails接口
        LoginUser loginUser = (LoginUser)authenticate.getPrincipal();

        Long id = loginUser.getUser().getId();

        String jwt = JwtUtil.createJWT(id.toString());

//      希望date数据中是  key:value的形式，所以用个map
        Map<String,String> map = new HashMap<>();
        map.put("token",jwt);

//      TODO 把完整的用户信息存入Redis, userId作为key
        redisCache.setCacheObject("login:"+id,loginUser);


        return new ResponseResult<>(200,"登录成功",map);

    }
}
