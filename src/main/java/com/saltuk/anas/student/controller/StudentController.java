package com.saltuk.anas.student.controller;

import com.saltuk.anas.student.model.Student;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("api/v1/students")
public class StudentController {

    private static List<Student> STUDENTS = List.of(
            new Student(1, "Annukov Alexey"),
            new Student(2, "Borisov Boris"),
            new Student(3, "Varyina Varvara")
    );

    @GetMapping(path = "/{id}")
    public Student getStudent(@PathVariable("id") Integer id) {
        return STUDENTS
                .stream()
                .filter(s -> s.id() == id)
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Student: " + id + "does not exist!"));
    }
}
