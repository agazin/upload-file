package com.agazin.demo;

import java.sql.Date;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Past;
import javax.websocket.server.PathParam;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonFormat.Shape;
import com.fasterxml.jackson.annotation.JsonProperty;

@RestController
public class ImportController {
	
	final static Logger logger = LoggerFactory.getLogger(ImportController.class);
	
	public static class FormRequest {
		public String fileHashId;
	}

	@PostMapping(value = "/upload" , headers = { "Authorization", "Accept-Language" })
	public void upload(@PathParam("file") MultipartFile file) {
		
		logger.info("uploaded : {}" , file.getOriginalFilename());
	}
	
	@GetMapping("/upload")
	public void hello() {
		logger.debug("hello");
	}
	

	@PostMapping("/valid")
	public void valid(@Valid @RequestBody FormRequest request) {
		logger.debug("request : {}", request.fileHashId);
	}
}
