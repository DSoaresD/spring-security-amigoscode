package com.example.demo.auth;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.example.demo.security.ApplicationUserRole;
import com.google.common.collect.Lists;

public class FakeApplicationUserDao implements ApplicationUserDao{
	
	private final PasswordEncoder passwordEncoder;	
	
	@Autowired
	public FakeApplicationUserDao(PasswordEncoder passwordEncoder) {
		this.passwordEncoder = passwordEncoder;
	}

	@Override
	public Optional<ApplicationUser> selectApplicationUserByUserName(String username) {
		return getApplicationUsers().stream().filter(applicationUser -> username.equals(applicationUser.getUsername())).findFirst();
	}
	
	private List<ApplicationUser> getApplicationUsers(){
		List<ApplicationUser> applicationUsers = Lists.newArrayList(
				new ApplicationUser(ApplicationUserRole.STUDENT.getGrantedAuthorities(),
						passwordEncoder.encode("password"), 
						"annasmith", true, true, true, true),
				
				new ApplicationUser(ApplicationUserRole.ADMIN.getGrantedAuthorities(),
						passwordEncoder.encode("password"), 
						"linda", true, true, true, true),
				
				new ApplicationUser(ApplicationUserRole.ADMINTRAINEE.getGrantedAuthorities(),
						passwordEncoder.encode("password"), 
						"tom", true, true, true, true));
		return applicationUsers;
		
	}

}
