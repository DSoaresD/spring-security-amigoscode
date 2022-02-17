package com.example.demo.students;

import java.util.Arrays;
import java.util.List;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("management/api/v1/students")
public class StudentManegementController {
	
	private static final List<Student> STUDENTS = Arrays.asList(
			new Student(1, "James Bond"),
			new Student (2,"Maria Jones"),
			new Student(3, "Anna Smith"));
	
	@GetMapping
	@PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_ADMINTRAINEE')")
	public List<Student> getAllStudent(){
		System.out.println("GetAllStudent");
		return STUDENTS;
	}
	@PostMapping
	@PreAuthorize("hasAuthority('student:write')")
	public void registerNewStudent(@RequestBody Student student) {
		System.out.println("RegisterNewStudent");
		System.out.println(student);
	}
	
	@DeleteMapping(value = "/{studentId}")
	@PreAuthorize("hasAuthority('student:write')")
	public void deleteStudent(Integer studentId) {
		System.out.println("DeletesNewStudent");
		System.out.println(studentId);
	}
	@PutMapping(value = "/{studentId}")
	@PreAuthorize("hasAuthority('student:write')")
	public void updateStudent(@PathVariable Integer studentId,@RequestBody Student student) {
		System.out.println("UpdateNewStudent");
		System.out.println(String.format(" %s %s", studentId, student));
	}

}
