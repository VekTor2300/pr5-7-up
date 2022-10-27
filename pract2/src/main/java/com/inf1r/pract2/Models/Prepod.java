package com.inf1r.pract2.Models;


import org.hibernate.validator.constraints.Range;

import javax.persistence.*;
import javax.validation.constraints.*;

@Entity
public class Prepod {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    @NotEmpty(message = "Ввод обязателен")
    @Size(min = 1, max = 100, message = "От 1 до 100 символов")
    private String surname, name;


    private Boolean checkstay;

    public String isStay(){
        return checkstay?"Да":"Нет";
    }

    @NotNull(message = "Ввод обязателен")
    @Range(min = 0, max = 300, message = "Значение от 0 до 300")
    private Integer hours;

    @NotNull(message = "Ввод обязателен")
    @DecimalMax(value = "200000.0", message = "Максимальное значение 200000.0 руб.") @DecimalMin("0.0")
    private Double salary;

    public Prepod(String Surname, String Name, Boolean CheckStay, Integer Hours, Double Salary) {
        this.surname = Surname;
        this.name = Name;
        this.checkstay = CheckStay;
        this.hours = Hours;
        this.salary = Salary;
    }

    public Prepod() {

    }


    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
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

    public Boolean getCheckstay() {
        return checkstay;
    }

    public void setCheckstay(Boolean checkstay) {
        this.checkstay = checkstay;
    }


    public Integer getHours() {
        return hours;
    }

    public void setHours(Integer hours) {
        this.hours = hours;
    }

    public Double getSalary() {
        return salary;
    }

    public void setSalary(Double salary) {
        this.salary = salary;
    }
}
