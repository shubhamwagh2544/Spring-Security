package com.springboot2.security.student;

import org.springframework.aop.target.LazyInitTargetSource;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.w3c.dom.stylesheets.LinkStyle;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("api/v1/students")
public class StudentController {

    private static List<Student> STUDENTS = Arrays.asList(
            new Student(1, "James Bond"),
            new Student(2, "John Wick"),
            new Student(3, "Ethan Hunt")
    );

    @GetMapping(path = "/{studentId}")
    public Student getStudent(@PathVariable Integer studentId) {
        return STUDENTS
                .stream()
                .filter(student -> student.getStudentId()==studentId)
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Student with student id " + studentId + " not found"));
    }
}
