package com.inf1r.pract2.Models;

import javax.persistence.*;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;
import javax.validation.constraints.Size;
import java.util.Collection;
import java.util.List;

@Entity
@Table(name = "college")
public class College {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    @NotEmpty(message = "Ввод обязателен")
    @Size(min = 1, max = 255, message = "От 1 до 255 символов")
    private String titlecollege;

    private Long NumTel;

    @OneToOne(optional = true, cascade = CascadeType.ALL)
    @JoinColumn(name = "address_id")
    private Address address;

    @ManyToMany
    @JoinTable(name = "StudCollege",
            joinColumns = @JoinColumn(name = "college_id"),
            inverseJoinColumns = @JoinColumn(name = "student_id"))
    private List<Student> studentList;

    public College(String titleCollege, Long NumTel, Address Adress, List<Student> studentList) {
        this.titlecollege = titleCollege;
        this.NumTel = NumTel;
        this.address = Adress;
        this.studentList = studentList;
    }

    public College() {

    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Long getNumTel() {
        return NumTel;
    }

    public void setNumTel(Long numTel) {
        NumTel = numTel;
    }

    public String getTitlecollege() {
        return titlecollege;
    }

    public void setTitlecollege(String titlecollege) {
        this.titlecollege = titlecollege;
    }

    public Address getAddress() {
        return address;
    }

    public void setAddress(Address address) {
        this.address = address;
    }

    public List<Student> getStudentList() {
        return studentList;
    }

    public void setStudentList(List<Student> studentList) {
        this.studentList = studentList;
    }
}
