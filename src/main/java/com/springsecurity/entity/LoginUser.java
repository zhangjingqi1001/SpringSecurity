package com.springsecurity.entity;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class LoginUser implements UserDetails {
    private User user;

    /**
     *
     * @return  获取权限信息
     */
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
//      返回权限信息的
        return null;
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
