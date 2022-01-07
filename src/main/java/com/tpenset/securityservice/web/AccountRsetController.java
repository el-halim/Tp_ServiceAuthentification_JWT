package com.tpenset.securityservice.web;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.tpenset.securityservice.JwtUtils;
import com.tpenset.securityservice.entites.AppRole;
import com.tpenset.securityservice.entites.AppUser;
import com.tpenset.securityservice.services.AccountService;
import lombok.Data;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.security.Principal;
import java.util.*;
import java.util.stream.Collectors;

@RestController
public class AccountRsetController {

private AccountService accountService;

    public AccountRsetController(AccountService accountService) {
        this.accountService = accountService;
    }

    @GetMapping(path = "/users")
    @PostAuthorize("hasAuthority('USER')")
public List<AppUser> appUsers(){
    return accountService.listUsers();
}

   @PostMapping(path = "/users")
   @PostAuthorize("hasAuthority('ADMIN')")
   public AppUser saveUser(@RequestBody AppUser appUser){

        return accountService.addNewUser(appUser);
   }

    @PostMapping(path = "/roles")
    @PostAuthorize("hasAuthority('ADMIN')")
    public AppRole saveRole(@RequestBody AppRole appRole){

        return accountService.addNewRole(appRole);
    }

    @PostMapping(path = "/addRoleToUser")
    public void addRoleToUser(@RequestBody RoleUserForm roleUserForm){

         accountService.addRoleToUser(roleUserForm.getUsername(),roleUserForm.getRolename());
    }

    @GetMapping(path = "/refreshToken")

    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws Exception{

        String authToken  = request.getHeader(JwtUtils.AUTH_HEADER);
       if(authToken != null && authToken.startsWith(JwtUtils.PREFIX)) {
           try {
               String jwt = authToken.substring(JwtUtils.PREFIX.length());
               Algorithm algorithm = Algorithm.HMAC256(JwtUtils.SECRET);
               JWTVerifier jwtVerifier = JWT.require(algorithm).build();
               DecodedJWT decodedJWT = jwtVerifier.verify(jwt);
               String username = decodedJWT.getSubject();
               AppUser appUser = accountService.loadUserByUsername(username);

               String jwtAccessToken= JWT
                       .create()
                       .withSubject(appUser.getUsername())
                       .withExpiresAt(new Date(System.currentTimeMillis()+JwtUtils.EXPIRE_ACCESS_TOKEN))
                       .withIssuer(request.getRequestURL().toString())
                       .withClaim("roles",appUser.getAppRoles().stream().map((r)->
                               r.getRoleName()).collect(Collectors.toList()))
                       .sign(algorithm);

               Map<String,String> idToken=new HashMap<>();
               idToken.put("Access_Token",jwtAccessToken);
               idToken.put("Refresh_Token",jwt);
               response.setContentType("application/json");
               new JsonMapper().writeValue(response.getOutputStream(),idToken);

           } catch (Exception e) {
               throw  e;
           }
       }
       else {
           throw  new RuntimeException("Refresh Token Required");
       }
    }

    @GetMapping(path = "/profile")
    public AppUser profile(Principal principal){
         return accountService.loadUserByUsername(principal.getName());
    }

}
@Data
class RoleUserForm{
    String username;
    String rolename;
}
