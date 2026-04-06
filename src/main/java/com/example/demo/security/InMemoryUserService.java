package com.example.demo.security;

import com.example.demo.entity.AppUser;
import com.example.demo.repository.UserRepository;
import jakarta.annotation.PostConstruct;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.util.Set;

@Service
public class InMemoryUserService implements UserDetailsService {

    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;

    public InMemoryUserService(PasswordEncoder passwordEncoder, UserRepository userRepository) {
        this.passwordEncoder = passwordEncoder;
        this.userRepository = userRepository;
    }

    @PostConstruct
    public void initDefaultUsers() {
        createIfAbsent("admin", "admin123", "admin@example.com", Set.of("ADMIN"));
        createIfAbsent("user", "user123", "user@example.com", Set.of("USER"));
    }

    private void createIfAbsent(String username, String rawPassword, String email, Set<String> roles) {
        if (!userRepository.existsByUsername(username)) {
            AppUser appUser = new AppUser(
                    username,
                    passwordEncoder.encode(rawPassword),
                    email,
                    roles
            );
            userRepository.save(appUser);
        }
    }

    @Transactional
    public void registerUser(String username, String rawPassword, String email) {
        String normalized = normalize(username);
        if (normalized == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Tên đăng nhập không hợp lệ");
        }
        if (rawPassword == null || rawPassword.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Mật khẩu không hợp lệ");
        }
        if (!isValidEmail(email)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Email không hợp lệ");
        }
        if ("admin".equalsIgnoreCase(normalized)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Tên đăng nhập đã tồn tại");
        }
        if (userRepository.existsByUsername(normalized)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Tên đăng nhập đã tồn tại");
        }
        AppUser newUser = new AppUser(
                normalized,
                passwordEncoder.encode(rawPassword),
                email.trim(),
                Set.of("USER")
        );
        userRepository.save(newUser);
    }

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        String normalized = normalize(username);
        if (normalized == null) {
            throw new UsernameNotFoundException("User not found");
        }
        AppUser record = userRepository.findByUsername(normalized)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        return User.builder()
                .username(record.getUsername())
                .password(record.getPasswordHash())
                .roles(record.getRoles().toArray(new String[0]))
                .build();
    }

    private String normalize(String username) {
        if (username == null) {
            return null;
        }
        String normalized = username.trim();
        return normalized.isEmpty() ? null : normalized;
    }

    private boolean isValidEmail(String email) {
        if (email == null) {
            return false;
        }
        String trimmed = email.trim();
        int at = trimmed.indexOf('@');
        if (at <= 0 || at == trimmed.length() - 1) {
            return false;
        }
        return trimmed.indexOf('.', at) > at + 1;
    }
}
