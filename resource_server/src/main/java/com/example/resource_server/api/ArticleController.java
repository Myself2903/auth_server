package com.example.resource_server.api;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ArticleController {
    @GetMapping("/articles")
    public String[] getArticles(){
        return new String[] {"article 1", "article 2", "article 3"};
    }
}
