package com.inf1r.pract2.Models;

import javax.persistence.*;
import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.Size;

@Entity
@Table(name = "address")
public class Address {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    @NotEmpty(message = "Ввод обязателен")
    @Size(min = 1, max = 200, message = "От 1 до 200 символов")
    private String adress;

    @OneToOne(cascade = CascadeType.ALL, orphanRemoval = true, mappedBy = "address")
    private College college;

    public Address(String Adress, College college){
        this.adress = Adress;
        this.college = college;
    }

    public Address() {

    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getAdress() {
        return adress;
    }

    public void setAdress(String adress) {
        this.adress = adress;
    }

    public College getCollege() {
        return college;
    }

    public void setCollege(College college) {
        this.college = college;
    }
}
