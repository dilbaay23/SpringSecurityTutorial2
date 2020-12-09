package com.moon.springsecuritytutorial2.student;

import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

/**
 * Created by Moon on 12/9/2020
 */

@RestController
@RequestMapping("management/api/v1/students")
public class StudentManagementController {

    private static final List<Student> STUDENTS = Arrays.asList(
            new Student(1,"Moon Koc"),
            new Student(2,"Lua As"),
            new Student(3,"Maan Laat")
    );

    @GetMapping
    public List<Student> getALlStudents(){
        return STUDENTS;
    }

    @PostMapping
    public void registerNewStudent(@RequestBody Student student){
        System.out.println(student);
    }

    @DeleteMapping(path = "{studentId}")
    public void deleteStudent(@PathVariable("studentId") Integer studentId){
        System.out.println(studentId);
    }

    @PutMapping(path = "{studentId}")
    public void updateStudent(@PathVariable("studentId") Integer studentId, @RequestBody Student student){
        System.out.println(String.format("%s %s" , studentId, student));
    }


}
