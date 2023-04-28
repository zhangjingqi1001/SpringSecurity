package com.springsecurity.entity;

import com.alibaba.fastjson.annotation.JSONField;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class LoginUser implements UserDetails {
    private User user;

//  存储权限信息
    private List<String>  permissions;

//  为什么什么这个成员变量？
//     如果每次请求都把权限字符串封装成下面的代码，比较耗时间，我们直接把他设置成成员变量
    @JSONField(serialize = false)  //这个属性不会序列化到我们的Redis中
    private  List<SimpleGrantedAuthority> authorities;

    public LoginUser(User user) {
        this.user = user;
    }

    public LoginUser(User user, List<String> permissions) {
        this.user = user;
        this.permissions = permissions;
    }

    /**
     *
     * @return  获取权限信息
     */
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
//      为什么什么这个成员变量？
//        如果每次请求都把权限字符串封装成下面的代码，比较耗时间，我们直接把他设置成成员变量

//        把permissions集合的String类型权限封装成Collection<? extends GrantedAuthority>的实现类SimpleGrantedAuthority
        if(authorities !=null){
            return authorities;
        }
         authorities = permissions.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());
//      返回权限信息的
        return authorities;
    }

    /**
     *   框架会调用LoginUser的getPassword方法获取当前用户的密码
     * @return   获取当前用户的密码
     */
    @Override
    public String getPassword() {

        return user.getPassword();
    }

    /**
     *
     * @return
     */
    @Override
    public String getUsername() {
        return user.getUserName();
    }

    /**
     * 判断是否没过期的
     *
     * @return false 代表超时
     */
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    /**
     * 是否可用
     *
     * @return
     */
    @Override
    public boolean isEnabled() {
        return true;
    }
}
