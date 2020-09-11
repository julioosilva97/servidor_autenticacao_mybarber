package com.mybarber.servidor_autentificacao.model;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.ArrayList;
import java.util.Collection;

public class Usuario {

    private int id;

    private String login;

    private String senha;

    private boolean ativo;

    private Perfil perfil;

    private Collection<GrantedAuthority> permissoes = new ArrayList<>();

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getLogin() {
        return login;
    }

    public void setLogin(String login) {
        this.login = login;
    }

    public String getSenha() {

        return senha;
    }

    public void setSenha(String senha) {
        if (senha != null) {
            this.senha = new BCryptPasswordEncoder().encode(senha);
        } else {
            this.senha = senha;
        }

    }

    public boolean isAtivo() {
        return ativo;
    }

    public void setAtivo(boolean ativo) {
        this.ativo = ativo;
    }


    public Perfil getPerfil() {
        return perfil;
    }

    public void setPerfil(Perfil perfil) {
        this.perfil = perfil;
    }

    public Collection<GrantedAuthority> getPermissoes() {
        return permissoes;
    }

    public void setPermissoes(Collection<GrantedAuthority> permissoes) {
        this.permissoes = permissoes;
    }

    public Usuario() {
    }

    public Usuario(int id, String login, String senha, boolean ativo, Perfil perfil) {
        this.id = id;
        this.login = login;
        this.senha = senha;
        this.ativo = ativo;
        this.perfil = perfil;
    }
}
