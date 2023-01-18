package io.getarrays.userservice.domain;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import javax.persistence.*;
import java.util.ArrayList;
import java.util.Collection;

@Entity
@Data   //so that you get getters and setters
@NoArgsConstructor    //no argument constructor
@AllArgsConstructor    //para constructor
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;
    private String name;
    private String username;
    private String password;

    @ManyToMany(fetch = FetchType.EAGER)  // When I load a user I want to load the roles too
    private Collection<Role> roles = new ArrayList<>();

}
