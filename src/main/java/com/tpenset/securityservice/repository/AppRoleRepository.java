package com.tpenset.securityservice.repository;

import com.tpenset.securityservice.entites.AppRole;
import com.tpenset.securityservice.entites.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AppRoleRepository extends JpaRepository<AppRole,Long> {
    AppRole findByRoleName(String rolename);
}
