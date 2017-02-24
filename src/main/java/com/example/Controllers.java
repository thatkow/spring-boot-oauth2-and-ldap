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
	@RequestMapping("/")
	public String query(Principal principal, Model model) {
		if (principal != null) {
			OAuth2Authentication oAuth2Authentication = (OAuth2Authentication) principal;
			Authentication authentication = oAuth2Authentication.getUserAuthentication();
			Map<String, String> details = new HashMap<String, String>();
			details = (Map<String, String>) authentication.getDetails();
			if (details.containsKey("email"))
				model.addAttribute("email", details.get("email"));
		}
		return "portal";
	}
}
