package com.tpenset.securityservice.services;

import com.tpenset.securityservice.entites.AppRole;
import com.tpenset.securityservice.entites.AppUser;
import com.tpenset.securityservice.repository.AppRoleRepository;
import com.tpenset.securityservice.repository.AppUserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.List;
@Service
@Transactional
public class AccountServiceImpl implements AccountService{

    private AppUserRepository appUserRepository;
    private AppRoleRepository appRoleRepository;

    private PasswordEncoder passwordEncoder;
    public AccountServiceImpl(AppUserRepository appUserRepository, AppRoleRepository appRoleRepository, PasswordEncoder passwordEncoder) {
        this.appUserRepository = appUserRepository;
        this.appRoleRepository = appRoleRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public AppUser addNewUser(AppUser appUser) {
        String pwd = appUser.getPassword();
        appUser.setPassword(passwordEncoder.encode(pwd));
        return appUserRepository.save(appUser);
    }

    @Override
    public AppRole addNewRole(AppRole appRole) {
        return appRoleRepository.save(appRole);
    }

    @Override
    public void addRoleToUser(String username, String rolename) {

        AppUser appUser = appUserRepository.findByUsername(username);
        AppRole appRole=appRoleRepository.findByRoleName(rolename);

        appUser.getAppRoles().add(appRole);

    }

    @Override
    public AppUser loadUserByUsername(String username) {
        return appUserRepository.findByUsername(username);
    }

    @Override
    public List<AppUser> listUsers() {
        return appUserRepository.findAll();
    }
}
