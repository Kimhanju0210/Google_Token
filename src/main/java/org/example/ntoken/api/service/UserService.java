package org.example.ntoken.api.service;

import lombok.RequiredArgsConstructor;
import org.example.ntoken.api.entity.user.User;
import org.example.ntoken.api.repository.user.UserRepository;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;

    public User getUser(String userId) {
        return userRepository.findByUserId(userId);
    }
}
