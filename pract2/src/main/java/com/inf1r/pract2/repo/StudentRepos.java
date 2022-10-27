package com.inf1r.pract2.repo;

import com.inf1r.pract2.Models.Student;
import org.springframework.data.repository.CrudRepository;

import java.util.List;

public interface StudentRepos extends CrudRepository<Student,Long> {
//    List<Student> findBySurnameContains(String surname);

    Student findBySurname(String surname);

}
