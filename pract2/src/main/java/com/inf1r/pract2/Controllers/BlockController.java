package com.inf1r.pract2.Controllers;

import com.inf1r.pract2.Models.*;
import com.inf1r.pract2.repo.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Optional;

@Controller
public class BlockController {
    @Autowired
    private PostRepos postRepos;

    @Autowired
    private PrepodRepos prepodRepos;

    @Autowired
    private StudentRepos studentRepos;

    @Autowired
    private GroupsRepos groupsRepos;

    @Autowired
    private CollegeRepos collegeRepos;

    @Autowired
    private AddressRepos addressRepos;

    @Autowired
    private UserRepos userRepos;

    @GetMapping("/")
    public String Main(Model model){
        return "Home";
    }

    @GetMapping("/blog")
    public String GetBlog(Model model){
        Iterable<Post> posts = postRepos.findAll();
        model.addAttribute("posts", posts);
        return "block-main";

    }

    @GetMapping("/studcollege")
    public String GetSC(Model model){
        Iterable<Student> students = studentRepos.findAll();
        model.addAttribute("students", students);
        Iterable<College> colleges = collegeRepos.findAll();
        model.addAttribute("college", colleges);
        return "StudentInCollege";

    }

    @GetMapping("/students")
    public String GetStudent(Model model){
        Iterable<Student> students = studentRepos.findAll();
        model.addAttribute("students",students);
        return "student-main";
    }
    @GetMapping("/prepods")
    public String GetPrepod(Model model){
        Iterable<Prepod> prepods = prepodRepos.findAll();
        model.addAttribute("prepods",prepods);
        return "prepod-main";
    }
    @GetMapping("/groups")
    public String GetGroups(Model model){
        Iterable<Groups> groups = groupsRepos.findAll();
        model.addAttribute("groups",groups);
        return "Groups/groups-main";
    }
    @GetMapping("/college")
    public String GetCollege(Model model){
        Iterable<College> colleges = collegeRepos.findAll();
        model.addAttribute("colleges",colleges);
        return "College/college-main";
    }
    @GetMapping("/address")
    public String GetAddress(User user, Model model){
        Iterable<Address> addresses = addressRepos.findAll();
        model.addAttribute("address",addresses);
        return "Address/address-main";
    }
    @GetMapping("/blog/add")
    public String blogAdd(Post post, Model model){
        return "block-add";
    }
    @GetMapping("/students/add")
    public String studentAdd(Student student, Model model){
        model.addAttribute("groupses", groupsRepos.findAll());
        return "student-add";
    }
    @GetMapping("/prepods/add")
    public String prepodAdd(Prepod prepod, Model model){
        return "prepod-add";
    }
    @GetMapping("/groups/add")
    public String groupsAdd(Groups groups, Model model){
        return "Groups/groups-add";
    }
    @GetMapping("/college/add")
    public String collegeAdd(College college, Model model){
        Iterable<Address> addresses = addressRepos.findAll();
        model.addAttribute("addressess", addresses);
        return "College/college-add";
    }
    @PostMapping("/college/add")
    public String collegeAdd(@ModelAttribute("college")@Valid College college,
                             BindingResult bindingResult, Model model){
        if(bindingResult.hasErrors()){
            Iterable<Address> addresses = addressRepos.findAll();
            model.addAttribute("addressess", addresses);
            return "College/college-add";
        }

        collegeRepos.save(college);
        return "redirect:/college";
    }

    @GetMapping("/address/add")
    public String addressAdd(Address address, Model model){
        return "Address/address-add";
    }

    @PostMapping("/blog/add")
    public String blogPostAdd(@ModelAttribute("post")@Validated Post post, BindingResult bindingResult){
        if(bindingResult.hasErrors()){
            return "block-add";
        }
        postRepos.save(post);
        return "redirect:/blog";
    }
    @PostMapping("/students/add")
    public Object studentAdd(@ModelAttribute("student")@Validated Student student, BindingResult bindingResult,
                             @RequestParam Long groups_id, Model model){
        model.addAttribute("groupses", groupsRepos.findAll());
        if(bindingResult.hasErrors()){
            return "student-add";
        }
        Groups groups;
        groups = groupsRepos.findById(groups_id).get();
        student.setGrups(groups);
        studentRepos.save(student);
        return "redirect:/students";
    }
//    @GetMapping("/students")
//    public String GetStudent(Model model){
//        Iterable<Student> students = studentRepos.findAll();
//        model.addAttribute("students",students);
//        return "student-main";
//    }
//    @GetMapping("/studcollege")
//    private String GetCollegeStud(Model model){
//        Iterable<Student> students = studentRepos.findAll();
//        model.addAttribute("students", students);
//        Iterable<College> colleges = collegeRepos.findAll();
//        model.addAttribute("colleges", colleges);
//
//        return "StudentInCollege";
//    }



    @GetMapping("/studcollege/add")
    public String CollegeStudAdd(Student student, College college, Model model){
        model.addAttribute("collegess", collegeRepos.findAll());
        model.addAttribute("studentess", studentRepos.findAll());
        return "StudentInCollege-add";
    }
    @PostMapping("/studcollege/add")
    public String CollegeStudAdd(@RequestParam String students, @RequestParam String colleges, Model model){
        Student student2 = studentRepos.findBySurname(students);
        College university2 = collegeRepos.findByTitlecollege(colleges);
        student2.getCollegeList().add(university2);
//        university2.getStudentList().add(student2);
        studentRepos.save(student2);
//        collegeRepos.save(university2);
        return "redirect:/studcollege";
    }

    @PostMapping("/prepods/add")
    public String prepodAdd(@ModelAttribute("prepod")@Validated Prepod prepod, BindingResult bindingResult){
        if(bindingResult.hasErrors()){
            return "prepod-add";
        }
        prepodRepos.save(prepod);
        return "redirect:/prepods";
    }
    @PostMapping("/groups/add")
    public String groupsAdd(@ModelAttribute("groups")@Validated Groups groups, BindingResult bindingResult){
        if(bindingResult.hasErrors()){
            return "Groups/groups-add";
        }
        groupsRepos.save(groups);
        return "redirect:/groups";
    }

    @PostMapping("/address/add")
    public String addressAdd(@ModelAttribute("address")@Validated Address address, BindingResult bindingResult){
        if(bindingResult.hasErrors()){
            return "Address/address-add";
        }
        addressRepos.save(address);
        return "redirect:/address";
    }

    @GetMapping("/blog/filter")
    public String blogFilter(Model model){
        return "block-filter";
    }
    @GetMapping("/students/filter")
    public String studentFilter(Model model){
        return "student-filter";
    }
    @GetMapping("/prepods/filter")
    public String prepodFilter(Model model){
        return "prepod-filter";
    }
    @GetMapping("/college/filter")
    public String collegeFilter(Model model){
        return "College/college-filter";
    }

    @PostMapping("/blog/filter/result")
    public String blogResult(@RequestParam String title, Model model){
        List<Post> result = postRepos.findByTitleContains(title);
        model.addAttribute("result", result);
        return "block-filter";
    }
    @PostMapping("/students/filter/result")
    public String studentResult(@RequestParam String surname, Model model){
        Student result = studentRepos.findBySurname(surname);
        model.addAttribute("result", result);
        return "student-filter";
    }
    @PostMapping("/prepods/filter/result")
    public String prepodResult(@RequestParam String surname, Model model){
        List<Prepod> result = prepodRepos.findBySurname(surname);
        model.addAttribute("result", result);
        return "prepod-filter";
    }
    @PostMapping("/college/filter/result")
    public String collegeResult(@RequestParam String titlecollege, Model model){
        College result = collegeRepos.findByTitlecollege(titlecollege);
        model.addAttribute("result", result);
        return "College/college-filter";
    }

    
    @GetMapping("/prepods/{id}")
    public String prepodViewing(@PathVariable(value = "id") long id, Model model){
        Optional<Prepod> prepodOptional = prepodRepos.findById(id);
        ArrayList<Prepod> res = new ArrayList<>();
        prepodOptional.ifPresent(res::add);
        model.addAttribute("prepod",res);
        if(!prepodRepos.existsById(id)){
            return "redirect:/prepods";
        }
        return "prepod-viewing";
    }
    @GetMapping("/prepods/{id}/edit")
    public String prepodEdit(@PathVariable("id") long id, Model model){
        Prepod res = prepodRepos.findById(id).orElseThrow(() -> new IllegalArgumentException("Неверный id: "+id));
        model.addAttribute("prepod", res);
        return "prepod-edit";
    }
    @PostMapping("/prepods/{id}/edit")
    public String prepodUpdate(@PathVariable("id") long id, @ModelAttribute("prepod")@Validated Prepod prepod, BindingResult bindingResult){
        prepod.setId(id);
        if(bindingResult.hasErrors()){
            return "prepod-edit";
        }
        prepodRepos.save(prepod);
        return "redirect:/prepods";
    }

    @PostMapping("/prepods/{id}/remove")
    public String prepodDelete(@PathVariable("id")long id, Model model){
        Prepod prepod = prepodRepos.findById(id).orElseThrow();
        prepodRepos.delete(prepod);
        return "redirect:/prepods";
    }




    @GetMapping("/students/{id}")
    public String studentViewing(@PathVariable(value = "id") long id, Model model){
        Optional<Student> studentOptional = studentRepos.findById(id);
        ArrayList<Student> res = new ArrayList<>();
        studentOptional.ifPresent(res::add);
        model.addAttribute("student",res);
        if(!studentRepos.existsById(id)){
            return "redirect:/students";
        }
        return "student-viewing";
    }



    @GetMapping("/students/{id}/edit")
    public String studentEdit(@PathVariable("id") long id, Model model){
        Student res = studentRepos.findById(id).orElseThrow(() -> new IllegalArgumentException("Неверный id: "+id));
        model.addAttribute("groupses", groupsRepos.findAll());
        model.addAttribute("collleges", collegeRepos.findAll());
        model.addAttribute("student", res);
        return "student-edit";
    }
    @PostMapping("/students/{id}/edit")
    public String studentUpdate(@PathVariable("id") long id, @ModelAttribute("student") @Validated Student student, BindingResult bindingResult,
                                @RequestParam Long groups_id,
                                @RequestParam Long colleges_id, Model model){
        model.addAttribute("groupses", groupsRepos.findAll());
        model.addAttribute("collleges", collegeRepos.findAll());
        student.setId(id);
        if(bindingResult.hasErrors()){
            return "student-edit";
        }
        Groups groups;
        groups = groupsRepos.findById(groups_id).get();
        student.setGrups(groups);
        List<College> coleges;
        coleges = (List<College>) collegeRepos.findById(colleges_id).get();
        student.setCollegeList(coleges);
        studentRepos.save(student);
        return "redirect:/students";
    }

    @PostMapping("/students/{id}/remove")
    public String studentDelete(@PathVariable("id")long id, Model model){
        Student student = studentRepos.findById(id).orElseThrow();
        studentRepos.delete(student);
        return "redirect:/students";
    }

    @GetMapping("/blog/{id}")
    public String blogViewing(@PathVariable(value = "id") long id, Model model){
        Optional<Post> postOptional = postRepos.findById(id);
        ArrayList<Post> res = new ArrayList<>();
        postOptional.ifPresent(res::add);
        model.addAttribute("post",res);
        if(!postRepos.existsById(id)){
            return "redirect:/blog";
        }
        return "block-viewing";
    }
    @GetMapping("/blog/{id}/edit")
    public String blogEdit(@PathVariable("id") long id, Model model){
        Post res = postRepos.findById(id).orElseThrow(() -> new IllegalArgumentException("Неверный id: "+id));
        model.addAttribute("post", res);
        return "block-edit";
    }
    @PostMapping("/blog/{id}/edit")
    public String blogUpdate(@PathVariable("id") long id, @ModelAttribute("post")@Validated Post post, BindingResult bindingResult){
        post.setId(id);
        if(bindingResult.hasErrors()){
            return "block-edit";
        }
        postRepos.save(post);
        return "redirect:/blog";
    }

    @PostMapping("/blog/{id}/remove")
    public String blogDelete(@PathVariable("id")long id, Model model){
        Post post = postRepos.findById(id).orElseThrow();
        postRepos.delete(post);
        return "redirect:/blog";
    }

    //GROUPS
    @GetMapping("/groups/{id}")
    public String groupsViewing(@PathVariable(value = "id") long id, Model model){
        Optional<Groups> groupsOptional = groupsRepos.findById(id);
        ArrayList<Groups> res = new ArrayList<>();
        groupsOptional.ifPresent(res::add);
        model.addAttribute("groups",res);
        if(!groupsRepos.existsById(id)){
            return "redirect:/groups";
        }
        return "Groups/groups-viewing";
    }
    @GetMapping("/groups/{id}/edit")
    public String groupsEdit(@PathVariable("id") long id, Model model){
        Groups res = groupsRepos.findById(id).orElseThrow(() -> new IllegalArgumentException("Неверный id: "+id));
        model.addAttribute("groups", res);
        return "Groups/groups-edit";
    }
    @PostMapping("/groups/{id}/edit")
    public String groupsUpdate(@PathVariable("id") long id, @ModelAttribute("prepod")@Validated Groups groups, BindingResult bindingResult){
        groups.setId(id);
        if(bindingResult.hasErrors()){
            return "Groups/groups-edit";
        }
        groupsRepos.save(groups);
        return "redirect:/groups";
    }

    @PostMapping("/groups/{id}/remove")
    public String groupsDelete(@PathVariable("id")long id, Model model){
        Groups groups = groupsRepos.findById(id).orElseThrow();
        groupsRepos.delete(groups);
        return "redirect:/groups";
    }

    //ADDRESS
//    @GetMapping("/address/{id}")
//    public String addressViewing(@PathVariable(value = "id") long id, Model model){
//        Optional<Address> addressOptional = addressRepos.findById(id);
//        ArrayList<Address> res = new ArrayList<>();
//        addressOptional.ifPresent(res::add);
//        model.addAttribute("address",res);
//        if(!addressRepos.existsById(id)){
//            return "redirect:/address";
//        }
//        return "Address/address-viewing";
//    }
    @GetMapping("/address/{id}/edit")
    public String addressEdit(@PathVariable("id") long id, Model model){
        Address res = addressRepos.findById(id).orElseThrow(() -> new IllegalArgumentException("Неверный id: "+id));
        model.addAttribute("address", res);
        return "Address/address-edit";
    }
    @PostMapping("/address/{id}/edit")
    public String addressUpdate(@PathVariable("id") long id, @ModelAttribute("address")@Validated Address address, BindingResult bindingResult){
        address.setId(id);
        if(bindingResult.hasErrors()){
            return "Address/address-edit";
        }
        addressRepos.save(address);
        return "redirect:/address";
    }

    @PostMapping("/address/{id}/remove")
    public String addressDelete(@PathVariable("id")long id, Model model){
        Address address = addressRepos.findById(id).orElseThrow();
        addressRepos.delete(address);
        return "redirect:/address";
    }

    //COLLEGE
    @GetMapping("/college/{id}")
    public String collegeViewing(@PathVariable(value = "id") long id, Model model){
        Optional<College> collegeOptional = collegeRepos.findById(id);
        ArrayList<College> res = new ArrayList<>();
        collegeOptional.ifPresent(res::add);
        model.addAttribute("college",res);
        if(!collegeRepos.existsById(id)){
            return "redirect:/college";
        }
        return "College/college-viewing";
    }
    @GetMapping("/college/{id}/edit")
    public String collegeEdit(@PathVariable("id") long id, Model model){
        College res = collegeRepos.findById(id).orElseThrow(() -> new IllegalArgumentException("Неверный id: "+id));
        Iterable<Address> addresses = addressRepos.findAll();
        model.addAttribute("addressess", addresses);
        model.addAttribute("college", res);
        return "College/college-edit";
    }
    @PostMapping("/college/{id}/edit")
    public String collegeUpdate(@PathVariable("id") long id, @ModelAttribute("address")@Validated College college, BindingResult bindingResult, Model model){
        college.setId(id);
        if(bindingResult.hasErrors()){
            Iterable<Address> addresses = addressRepos.findAll();
            model.addAttribute("addressess", addresses);
            return "College/college-edit";
        }
        collegeRepos.save(college);
        return "redirect:/college";
    }

    @PostMapping("/college/{id}/remove")
    public String collegeDelete(@PathVariable("id")long id, Model model){
        College college = collegeRepos.findById(id).orElseThrow();
        collegeRepos.delete(college);
        return "redirect:/college";
    }

}
