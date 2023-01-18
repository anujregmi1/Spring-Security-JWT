package io.getarrays.userservice.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import static java.util.Arrays.stream;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@Slf4j
public class CustomAuthorizationFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        //check if they are trying to login, if so allow everyone
        if(request.getServletPath().equals("/api/login") || request.getServletPath().equals("/api/token/refresh")){
            //dont do anything. Make this filter pass the request to the next filter in the filter chain
            filterChain.doFilter(request,response);
        } else {
            //get the header from the request that has the key authorization
            String authorizationHeader = request.getHeader(AUTHORIZATION);
            if(authorizationHeader != null && authorizationHeader.startsWith("Bearer ")){
                try {
                    //get the token without the Bearer
                    String token = authorizationHeader.substring("Bearer ".length());

                    //define the algorithm
                    Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());

                    JWTVerifier verifier = JWT.require(algorithm).build(); //create the verifier
                    DecodedJWT decodedJWT = verifier.verify(token);   //get the decoded token after verifying


                    String username = decodedJWT.getSubject();     //get the username that comes with the token
                    String[] roles = decodedJWT.getClaim("roles").asArray(String.class);  //get all the user roles in an array

                    System.out.println(roles);
                    //convert that role into a collection of authorities of type SimpleGrantedAuthority
                    Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
                    stream(roles).forEach(role -> {
                        authorities.add(new SimpleGrantedAuthority(role));
                    });

                    UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, null, authorities);
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                    filterChain.doFilter(request,response);

                } catch(Exception exception){

                    log.error("Error logging in: {}", exception.getMessage());
                    response.setHeader("error", exception.getMessage());
                    response.setStatus(FORBIDDEN.value());
                    //response.sendError(FORBIDDEN.value());

                    Map<String, String> error = new HashMap<>();

                    error.put("error_message", exception.getMessage());

                    response.setContentType(APPLICATION_JSON_VALUE);
                    new ObjectMapper().writeValue(response.getOutputStream(), error);
                }
            } else {
                filterChain.doFilter(request,response);
            }
        }
    }
}
