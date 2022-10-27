package com.inf1r.pract2.repo;

import com.inf1r.pract2.Models.Groups;
import org.springframework.data.repository.CrudRepository;

import java.util.List;

public interface GroupsRepos extends CrudRepository<Groups,Long> {
    List<Groups> findByGroupsContains(Integer groups);
}
