package com.inf1r.pract2.repo;

import com.inf1r.pract2.Models.User;
import org.springframework.data.repository.CrudRepository;

import java.util.List;

public interface UserRepos extends CrudRepository<User,Long> {
    User findByLogin(String username);

}
