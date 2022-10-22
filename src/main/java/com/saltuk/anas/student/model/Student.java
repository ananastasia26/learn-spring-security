package com.saltuk.anas.student.model;

public record Student(Integer id, String fullName) {
    @Override
    public String toString() {
        return "Student{" +
                "id=" + id +
                ", fullName='" + fullName + '\'' +
                '}';
    }
}
