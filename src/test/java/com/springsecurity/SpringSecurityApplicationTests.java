package com.springsecurity;

import com.springsecurity.entity.User;
import com.springsecurity.mapper.MenuMapper;
import com.springsecurity.service.UserService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.List;

@SpringBootTest
class SpringSecurityApplicationTests {

    @Autowired
    private UserService userService;

    @Autowired
    private MenuMapper  menuMapper;

    @Test
    void contextLoads() {
//        BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
//        String encode = bCryptPasswordEncoder.encode("1234");
//        System.out.println(encode);
        List<String> list = menuMapper.selectPermsByUserId(2L);
        System.out.println(list);

    }

}
