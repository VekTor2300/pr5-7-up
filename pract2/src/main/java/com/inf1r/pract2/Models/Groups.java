package com.inf1r.pract2.Models;

import org.hibernate.validator.constraints.Range;

import javax.persistence.*;
import javax.validation.constraints.NotNull;
import java.util.Collection;

@Entity
@Table(name = "grups")
public class Groups {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    @NotNull(message = "Ввод обязателен")
    @Range(min=0, max=90, message = "Диапазон от 0 до 90")
    private Integer groups;

    @OneToMany(mappedBy = "grups", fetch = FetchType.EAGER, cascade = CascadeType.ALL)
    private Collection<Student> students;

    public Groups(Long id, Integer groups, Collection<Student> students1) {
        this.id = id;
        this.groups = groups;
        this.students = students1;
    }

    public Groups() {

    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Integer getGroups() {
        return groups;
    }

    public void setGroups(Integer groups) {
        this.groups = groups;
    }

    public Collection<Student> getStudents() {
        return students;
    }

    public void setStudents(Collection<Student> students) {
        this.students = students;
    }
}
