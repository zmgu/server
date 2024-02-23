package com.ex.server.mapper;

import com.ex.server.dto.User;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface UserMapper {

    User findByUsername(String username) throws Exception;

    void save(User user) throws Exception;

    void oauthSave(User user) throws Exception;

    void update(User user) throws Exception;

    int insert(User user) throws Exception;
}
