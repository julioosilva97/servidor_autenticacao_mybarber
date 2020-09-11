package com.mybarber.servidor_autentificacao.config;

  
  
  import javax.annotation.PostConstruct;
  
  import org.springframework.beans.factory.annotation.Autowired; import
  org.springframework.jdbc.core.JdbcTemplate; import
  org.springframework.security.crypto.password.PasswordEncoder; import
  org.springframework.stereotype.Component;
  
  @Component class UserCreator {
  
  @Autowired private JdbcTemplate jdbcTemplate;
  
  String salvarSenha = "UPDATE usuario set senha=? WHERE id = 1";
  
  @Autowired private PasswordEncoder passwordEncoder;
  
  @PostConstruct public void init() {
  
  jdbcTemplate.update(salvarSenha,passwordEncoder.encode("123"));
  
  
  } }
 