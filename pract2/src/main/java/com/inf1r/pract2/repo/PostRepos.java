package com.inf1r.pract2.repo;

import com.inf1r.pract2.Models.Post;
import org.springframework.data.repository.CrudRepository;

import java.util.List;

public interface PostRepos extends CrudRepository<Post,Long> {
    List<Post> findByTitleContains(String title);

}
