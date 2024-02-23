package com.ex.server.controller;

import com.ex.server.dto.PrincipalDetails;
import com.ex.server.dto.User;
import com.ex.server.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    /**
     * 사용자 정보 조회
     * @param customUser
     * @return
     */
    @Secured({"ROLE_USER", "ROLE_ADMIN"})           // USER 권한 설정
    @GetMapping("/info")
    public ResponseEntity<?> userInfo(@AuthenticationPrincipal PrincipalDetails customUser) {

        log.info("::::: customUser :::::");
        log.info("customUser : "+ customUser);

        User user = customUser.getUser();
        log.info("user : " + user);

        // 인증된 사용자 정보
        if( user != null )
            return new ResponseEntity<>(user, HttpStatus.OK);

        // 인증 되지 않음
        return new ResponseEntity<>("UNAUTHORIZED", HttpStatus.UNAUTHORIZED);
    }

    @PostMapping("")
    public ResponseEntity<?> join(@RequestBody User user) throws Exception {
        log.info("[POST] - /users");
        int result = userService.insert(user);

        if( result > 0 ) {
            log.info("회원가입 성공! - SUCCESS");
            return new ResponseEntity<>("SUCCESS", HttpStatus.OK);
        }
        else {
            log.info("회원가입 실패! - FAIL");
            return new ResponseEntity<>("FAIL", HttpStatus.BAD_REQUEST);
        }
    }
}
