package com.example.demo.security;

import com.example.demo.entity.AppUser;
import com.example.demo.repository.UserRepository;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.Set;
import java.util.regex.Pattern;

@Service
public class AppUserService implements UserDetailsService {

    private static final Logger log = LoggerFactory.getLogger(AppUserService.class);
    private static final Pattern EMAIL_PATTERN = Pattern.compile("^[A-Za-z0-9+_.-]+@(.+)$");

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public AppUserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @PostConstruct
    public void initDefaultUsers() {
        if (!userRepository.existsByUsername("admin")) {
            addFixedUser("admin", "admin123", "admin@example.com", Set.of("ADMIN", "USER"));
        }
        if (!userRepository.existsByUsername("user")) {
            addFixedUser("user", "user123", "user@example.com", Set.of("USER"));
        }
        if (!userRepository.existsByUsername("demo")) {
            addFixedUser("demo", "demo123", "demo@example.com", Set.of("USER"));
        }
        log.info("Initialized fixed login accounts in database.");
    }

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
        if (userRepository.existsByUsername(normalized)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Tên đăng nhập đã tồn tại");
        }
        if (userRepository.existsByEmail(email.trim())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Email đã được sử dụng");
        }

        AppUser user = new AppUser(
                normalized,
                passwordEncoder.encode(rawPassword),
                email.trim(),
                Set.of("USER")
        );
        userRepository.save(user);
        log.info("Registered user in database: {}", normalized);
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        String normalized = normalize(username);
        if (normalized == null) {
            throw new UsernameNotFoundException("User not found");
        }

        AppUser user = userRepository.findByUsername(normalized)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + normalized));

        return User.builder()
                .username(user.getUsername())
                .password(user.getPasswordHash())
                .roles(user.getRoles().toArray(new String[0]))
                .build();
    }

    private void addFixedUser(String username, String rawPassword, String email, Set<String> roles) {
        AppUser user = new AppUser(
                username,
                passwordEncoder.encode(rawPassword),
                email,
                roles
        );
        userRepository.save(user);
    }

    private String normalize(String username) {
        if (username == null) {
            return null;
        }
        String normalized = username.trim().toLowerCase();
        return normalized.isEmpty() ? null : normalized;
    }

    private boolean isValidEmail(String email) {
        if (email == null || email.isBlank()) {
            return false;
        }
        return EMAIL_PATTERN.matcher(email).matches();
    }
}
