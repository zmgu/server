package com.ex.server.dto;

import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;

import static com.ex.server.dto.role.ROLE_USER;

@Data
@NoArgsConstructor
public class User {
    private int id;
    private String username;
    private String password;
    private String role;
    private String name;
    private String email;
    private Date regDate;
    private Date updDate;
    private int enabled;            // 활성화 여부

    public User(User user) {
        this.id = id;
        this.username = username;
        this.password = password;
        this.role = ROLE_USER;
        this.name = name;
        this.email = email;
        this.regDate = regDate;
        this.updDate = updDate;
        this.enabled = enabled;
    }
}
