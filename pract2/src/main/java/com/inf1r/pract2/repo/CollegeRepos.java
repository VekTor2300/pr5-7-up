package com.inf1r.pract2.repo;

import com.inf1r.pract2.Models.College;
import org.springframework.data.repository.CrudRepository;

import java.util.List;

public interface CollegeRepos extends CrudRepository<College,Long> {
//    List<College> findBytitlecollegeContains(String titlecollege);

    College findByTitlecollege(String titlecollege);

}
