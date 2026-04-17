package br.ufsc.labsec.pbad.selectionchallengepsc.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

@RestController
@RequestMapping("/redirect")
public class RedirectController {

    @GetMapping(path = "/{userId}", produces = "text/html")
    public ModelAndView redirectPage(
            @PathVariable String userId,
            String state,
            String code) {
        
        ModelAndView modelAndView = new ModelAndView("redirect");
        modelAndView.addObject("userId", userId);
        modelAndView.addObject("state", state != null ? state : "");
        modelAndView.addObject("code", code != null ? code : "None (User rejected formatting or missing code)");
        
        return modelAndView;
    }
}
