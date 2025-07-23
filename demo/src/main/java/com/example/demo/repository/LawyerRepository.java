package com.example.demo.repository;

import com.example.demo.entity.Lawyer;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface LawyerRepository extends JpaRepository<Lawyer, Long> {
  Optional<Lawyer> findByUsername(String username);
  boolean existsByUsername(String username);
}
