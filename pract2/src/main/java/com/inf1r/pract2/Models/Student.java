package com.inf1r.pract2.Models;

import org.hibernate.validator.constraints.Range;
import org.springframework.format.annotation.DateTimeFormat;

import javax.persistence.*;
import javax.validation.constraints.*;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

@Entity
@Table(name = "student")
public class Student {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    @NotEmpty(message = "Ввод обязателен")
    @Size(min = 1, max = 100, message = "От 1 до 100 символов")
    private String surname, name;

    @NotNull(message = "Ввод обязателен")
    @DecimalMax(value = "15000.0", message = "Максимальное значение 15000 руб.") @DecimalMin("0.0")
    private Double Scholarship;

    @NotNull(message = "Необходимо ввести дату")
    @DateTimeFormat(pattern = "yyyy-MM-dd")
    @Temporal(TemporalType.DATE)
    @PastOrPresent(message = "Дата не может быть настоящей или будущей")
    private Date birthday;

    @ManyToOne(optional = true, cascade = CascadeType.DETACH)
    private Groups grups;

    @ManyToMany
    @JoinTable(name = "StudCollege",
    joinColumns = @JoinColumn(name = "student_id"), inverseJoinColumns = @JoinColumn(name = "college_id"))
    private List<College> collegeList;


    public Student(String Surname, String Name, Double Scholarship, Date Birthday, Groups grups, College colleges, List<College> collegeList) {
        this.surname = Surname;
        this.name = Name;
        this.Scholarship = Scholarship;
        this.birthday = Birthday;
        this.grups = grups;
        this.collegeList = collegeList;
    }

    public Student() {

    }

    public String getSurname() {
        return surname;
    }

    public void setSurname(String surname) {
        this.surname = surname;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Double getScholarship() {
        return Scholarship;
    }

    public void setScholarship(Double Scholarship) {
        this.Scholarship = Scholarship;
    }



    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }


    public Date getBirthday() {

        return birthday;
    }

    public void setBirthday(Date birthday) {
        this.birthday = birthday;
    }

    public String getBirthdayString(){
        return new SimpleDateFormat("yyyy-MM-dd").format(this.getBirthday());
    }

    public Groups getGrups() {
        return grups;
    }

    public void setGrups(Groups grups) {
        this.grups = grups;
    }

    public List<College> getCollegeList() {
        return collegeList;
    }

    public void setCollegeList(List<College> collegeList) {
        this.collegeList = collegeList;
    }
}
