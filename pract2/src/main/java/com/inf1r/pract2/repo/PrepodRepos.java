package com.inf1r.pract2.repo;

import com.inf1r.pract2.Models.Prepod;
import org.springframework.data.repository.CrudRepository;

import java.util.List;

public interface PrepodRepos extends CrudRepository<Prepod,Long>{
    List<Prepod> findBySurname(String surname);

}
