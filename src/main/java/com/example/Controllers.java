package com.example;

import java.security.Principal;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

@Controller
@Configuration
public class Controllers {

	@Value("${ldap.source.name:null}")
	private String ldapSourceName;

	@Value("${ldap.source.image:null}")
	private String ldapSourceImage;

	@Autowired
	ApplicationContext applicationContext;

	private boolean isOauth2Defined(ApplicationContext applicationContext, String name) {
		return applicationContext.containsBean(name);
	}

	@RequestMapping({ "/login" })
	public String query(Principal principal, Model model) {
		model.addAttribute("ldapSourceName", ldapSourceName);
		model.addAttribute("ldapSourceImage", ldapSourceImage);

		model.addAttribute("googleBeanDefined", isOauth2Defined(applicationContext, "google"));
		model.addAttribute("githubBeanDefined", isOauth2Defined(applicationContext, "github"));
		model.addAttribute("facebookBeanDefined", isOauth2Defined(applicationContext, "facebook"));
		model.addAttribute("ldapBeanDefined", isOauth2Defined(applicationContext, "ldap"));

		return "portal";
	}

	@RequestMapping(path = "/logout", method = RequestMethod.POST)
	public String logout() {
		return "redirect:/login";
	}

	@RequestMapping("/home")
	public String home(Principal principal, Model model) {
		if (principal != null) {
			if (principal instanceof OAuth2Authentication) {
				OAuth2Authentication authentication = (OAuth2Authentication) principal;
				@SuppressWarnings("unchecked")
				Map<String, String> details = (Map<String, String>) authentication.getUserAuthentication().getDetails();
				if (details.containsKey("username")) {
					model.addAttribute("username", details.get("username"));
				} else if (details.containsKey("name")) {
					model.addAttribute("username", details.get("name"));
				}
				if (details.containsKey("email"))
					model.addAttribute("email", details.get("email"));
				if (details.containsKey("picture"))
					model.addAttribute("picture", details.get("picture"));
			} else if (principal instanceof UsernamePasswordAuthenticationToken) {
				// No email available for this one
			}
			String name = principal.getName();
			if (!model.containsAttribute("username") && name != null && !name.isEmpty()) {
				model.addAttribute("username", name);
			}
		}
		return "home";
	}

}