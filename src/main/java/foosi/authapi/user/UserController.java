package foosi.authapi.user;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/users")
public class UserController {

	@Autowired
    private ApplicationUserRepository applicationUserRepository;
	
	@Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

	/**
	 * save the user sign up information, including the user name and encoded password
	 *  
	 *  
	 * @param user
	 */
    @PostMapping("/sign-up")
    public void signUp(@RequestBody ApplicationUser user) {
    	
    	// when sign up, encode the password
    	
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        
        System.out.println("user" + user.getUsername() + " password: " + user.getPassword());
        
        applicationUserRepository.save(user);
    }
}