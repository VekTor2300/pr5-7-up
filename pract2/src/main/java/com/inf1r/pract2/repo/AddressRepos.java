package com.inf1r.pract2.repo;

import com.inf1r.pract2.Models.Address;
import com.inf1r.pract2.Models.College;
import org.springframework.data.repository.CrudRepository;

import java.util.List;

public interface AddressRepos extends CrudRepository<Address,Long> {
    List<Address> findByadressContains(String adress);
}
