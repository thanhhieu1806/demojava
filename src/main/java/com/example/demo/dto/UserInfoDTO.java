package com.example.demo.dto;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.Set;
import java.util.stream.Collectors;

public record UserInfoDTO(
        String username,
        String role,
        Set<String> authorities,
        boolean authenticated
) {
    public static UserInfoDTO fromAuthentication(Authentication authentication){
        if(authentication == null
                || !authentication.isAuthenticated()
                || authentication instanceof AnonymousAuthenticationToken
                || authentication.getAuthorities().stream()
                    .anyMatch(a -> "ROLE_ANONYMOUS".equals(a.getAuthority()))){
            return new UserInfoDTO(null,null, Set.of(),false);
        }
        String role = authentication.getAuthorities().stream()
                .filter(a -> a.getAuthority().startsWith("ROLE_"))
                .map(a ->a.getAuthority().substring("ROLE_".length()))
                .findFirst()
                .orElse("USER");

        Set<String> authorities=authentication.getAuthorities().stream()
                .map(GrantedAuthority:: getAuthority)
                .collect(Collectors.toSet());


        return new UserInfoDTO(
                authentication.getName(),
                role,
                authorities,
                true
        );
    }
}
