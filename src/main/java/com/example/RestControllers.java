package com.example;

import java.security.Principal;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class RestControllers {
	@RequestMapping("/user")
	public Principal userName(Principal principal) {
		return principal;
	}
}
