package com.example.demo.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class ClientForwardController {

    @GetMapping(value = {
            "/",
            "/{path:[^\\.]*}",
            "/**/{path:[^\\.]*}"
    })
    public String forward(jakarta.servlet.http.HttpServletRequest request) {
        String path = request.getRequestURI();
        if (path.startsWith("/api") || path.startsWith("/logout") || path.startsWith("/static")) {
            return null; // Trả về null để Spring tiếp tục tìm handler khác (như AuthController)
        }
        return "forward:/index.html";
    }
}
