package mate.academy.controller;

import javax.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class IndexController {
    @GetMapping("/")
    public String hello(HttpServletRequest request) {
        String sessionId = request.getSession().getId();
        return String.format("Hello, ex NPE "
                + ". Your session id is: " + sessionId);
    }
}
