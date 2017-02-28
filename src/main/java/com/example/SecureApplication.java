
package com.example;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

@SpringBootApplication
public class SecureApplication extends WebMvcConfigurerAdapter {
	public static void main(String[] args) throws Exception {
		SpringApplication.run(SecureApplication.class, args);
	}
}
