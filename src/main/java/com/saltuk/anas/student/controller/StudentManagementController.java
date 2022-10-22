package com.saltuk.anas.student.controller;

import com.saltuk.anas.student.model.Student;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("management/api/v1/students")
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class StudentManagementController {

    private static List<Student> STUDENTS = List.of(
            new Student(1, "Annukov Alexey"),
            new Student(2, "Borisov Boris"),
            new Student(3, "Varyina Varvara")
    );

    @GetMapping
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_ADMINTRAINEE')")
    public List<Student> getStudents() {
        System.out.println("getStudents");
        return STUDENTS;
    }

    @PostMapping
    @PreAuthorize("hasAuthority('student:write')")
    public void register(@RequestBody Student student) {
        System.out.println("register");
        System.out.println(student);
    }

    @PutMapping(value = "/{studentId}")
    @PreAuthorize("hasAuthority('student:write')")
    public void update(@PathVariable("studentId") Integer studentId, @RequestBody Student student) {
        System.out.println("update");
        System.out.printf("%s %s%n", studentId, student);
    }

    @DeleteMapping(value = "/{studentId}")
    @PreAuthorize("hasAuthority('student:write')")
    public void delete(@PathVariable("studentId") Integer studentId) {
        System.out.println("delete");
        System.out.printf("%s", studentId);
    }
}
