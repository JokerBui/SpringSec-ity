package com.example.demo.service;

import com.example.demo.model.User;
import java.util.List;

import java.util.Optional;

public interface IUserService {
    Optional<User> findByUserName(String name);

    Boolean existsByUserName(String username);

    Boolean existsByEmail (String email);
    User save(User user);

}
