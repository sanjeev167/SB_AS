package com.pon;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
@RestController
@SpringBootApplication
public class SbAsApplication {

	public static void main(String[] args) {
		SpringApplication.run(SbAsApplication.class, args);
	}
	
	@GetMapping("/")
	public String welcome() {		
		return "Hi Sanjeev";
	}
}