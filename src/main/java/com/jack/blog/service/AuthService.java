package com.jack.blog.service;

import com.jack.blog.dto.LoginRequest;
import com.jack.blog.dto.RegisterRequest;
import com.jack.blog.model.User;
import com.jack.blog.repository.UserRepository;
import com.jack.blog.security.JwtProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

  @Autowired private UserRepository userRepository;
	@Autowired
	PasswordEncoder passwordEncoder;

	@Autowired
	private AuthenticationManager authenticationManager;
	@Autowired
	private JwtProvider jwtProvider;


  public void signUp(RegisterRequest registerRequest) {
    User user = new User();
    user.setUserName(registerRequest.getUserName());
    user.setPassword(encodePassword(registerRequest.getPassword()));
    user.setEmail(registerRequest.getEmail());

    userRepository.save(user);
  }

	private String encodePassword(String password) {
  		return passwordEncoder.encode(password);
	}


	public void login(LoginRequest loginRequest) {
		Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUserName(), loginRequest.getPassword()));
		SecurityContextHolder.getContext().setAuthentication(authentication);
  		jwtProvider.generateToken(authentication);
  }
}
