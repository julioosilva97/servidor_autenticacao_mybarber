package com.mybarber.servidor_autentificacao;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;

@SpringBootApplication
@EnableResourceServer
public class ServidorAutentificacaoApplication {

	public static void main(String[] args) {
		SpringApplication.run(ServidorAutentificacaoApplication.class, args);

		System.out.println("Foi porra :)");
	}

}
