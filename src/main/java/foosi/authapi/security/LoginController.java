package foosi.authapi.security;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

import foosi.authapi.user.ApplicationUser;

@Controller
@RequestMapping("/auth")
public class LoginController {

    @GetMapping("/loginx")
    public String loginx() {
    	return "login";
    }
    
    
    @GetMapping("/login")
    public ModelAndView login(
    		@RequestParam(value = "error", required = false) String error,
    		@RequestParam(value = "logout", required = false) String logout) {
    	
    	ModelAndView model = new ModelAndView();
    	model.setViewName("login");    	
    	
		if (error != null) {
			model.addObject("message", "Invalid username and password!");
		}

		if (logout != null) {
			model.addObject("message", "You've been logged out successfully.");
		}    	
    	
    	
    	return model;
    }    
    
}
