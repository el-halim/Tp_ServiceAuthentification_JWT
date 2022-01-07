package com.tpenset.securityservice.repository;

import com.tpenset.securityservice.entites.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AppUserRepository extends JpaRepository<AppUser,Long> {

    AppUser findByUsername(String username);
}
