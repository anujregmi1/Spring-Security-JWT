package io.getarrays.userservice.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@Slf4j
public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    //use AuthenticationManager to authenticate the user that takes in user credentials like username and password
    private final AuthenticationManager authenticationManager;

    //constructor
    public CustomAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        //get the username and password from the request
        String username = request.getParameter("username");
        String password = request.getParameter("password");

        log.info("Username is {}", username); log.info("Password is: {}", password);

        //create auth token using username and password
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, password);

        //use the authentication manager to authenticate the user with that credential
        return authenticationManager.authenticate(authenticationToken);
    }

    //this is where we generate the token, sign it and send that to the user
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) throws IOException, ServletException {

        //get the user from spring security, it's the user that has been successfully authenticated
        User user = (User)authentication.getPrincipal();

        //use an algorithm that you use to sign the json web token
        Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());

        //create the token
        String access_token = JWT.create()
                .withSubject(user.getUsername())   //with username/ has to be unique
                .withExpiresAt(new Date(System.currentTimeMillis() + 10*60*1000))   //expiring time
                .withIssuer(request.getRequestURL().toString())    //url of our application
                .withClaim("roles", user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))   //pass all the roles of the user
                .sign(algorithm); //sign using the algorithm

        //create refresh token
        String refresh_token = JWT.create()
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + 30*60*1000))
                .withIssuer(request.getRequestURL().toString())
                .sign(algorithm);

//        response.setHeader("access_token", access_token);
//        response.setHeader("refresh_token", refresh_token);

        //return in a JSON format
        Map<String, String> tokens = new HashMap<>();

        tokens.put("access_token", access_token);
        tokens.put("refresh_token", refresh_token);

        response.setContentType(APPLICATION_JSON_VALUE);
        new ObjectMapper().writeValue(response.getOutputStream(), tokens);


    }
}
