package com.springsecurity.mapper;

import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.springsecurity.entity.User;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface UserMapper extends BaseMapper<User> {
}
