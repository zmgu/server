package com.ex.server.service;

import com.ex.server.dto.PrincipalDetails;
import com.ex.server.dto.User;
import com.ex.server.mapper.UserMapper;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class CustomUserDetailService implements UserDetailsService {

    @Autowired
    private UserMapper userMapper;

    @SneakyThrows
    @Override
    public UserDetails loadUserByUsername(String username)  {
        log.info("login - loadUserByUsername : " + username);

        User user = userMapper.findByUsername(username);

        if( user == null ) {
            log.info("사용자 없음... (일치하는 아이디가 없음)");
            throw new UsernameNotFoundException("사용자를 찾을 수 없습니다 : " + username);
        }

        log.info("user : ");
        log.info(user.toString());

        // Users -> CustomUser
        PrincipalDetails customUser = new PrincipalDetails(user);

        log.info("customUser : ");
        log.info(customUser.toString());

        return customUser;
    }


}