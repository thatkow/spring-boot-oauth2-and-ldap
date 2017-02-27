package com.example;

import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class Controllers {

	@SuppressWarnings("unchecked")
	@RequestMapping({ "/", "/home" })
	public String query(Principal principal, Model model) {
		if (principal != null) {
			if (principal instanceof OAuth2Authentication) {
				OAuth2Authentication oAuth2Authentication = (OAuth2Authentication) principal;
				Authentication authentication = oAuth2Authentication.getUserAuthentication();
				Map<String, String> details = new HashMap<String, String>();
				details = (Map<String, String>) authentication.getDetails();
				if (details.containsKey("email"))
					model.addAttribute("email", details.get("email"));
			}
			String name = principal.getName();
			model.addAttribute("name", name);
		}
		return "home";
	}

	@RequestMapping(path = { "/portal", "/login" })
	public String login() {
		return "portal";
	}

	@RequestMapping(path = { "/login?logout" })
	public String loginLogout() {
		return "portal";
	}

	@RequestMapping(path = { "/login?error" })
	public String loginError() {
		return "portal";
	}

}
