package com.agazin.demo.config;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.servlet.FilterChain;
import javax.servlet.ReadListener;
import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;

import org.apache.logging.log4j.ThreadContext;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.ContentCachingRequestWrapper;
import org.springframework.web.util.ContentCachingResponseWrapper;

import com.agazin.demo.config.utility.JwtUtil;


@Configuration
@Order(2)
public class RequestResponseLogFilter extends OncePerRequestFilter {

	private static final Logger logger = LoggerFactory.getLogger(RequestResponseLogFilter.class);
	private static final String CLINET_IP = "CLIENT_IP";
	private static final String USER_NAME = "USER_NAME";
	private static final String OAUTH_CLIENT_ID = "OAUTH_CLIENT_ID";
	private AntPathMatcher pathMatcher = new AntPathMatcher();

	private static final List<MediaType> VISIBLE_TYPES = Arrays.asList(MediaType.valueOf("text/*"),
			MediaType.APPLICATION_FORM_URLENCODED
			, MediaType.APPLICATION_JSON
			, MediaType.APPLICATION_XML
			, MediaType.valueOf("application/*+json")
			, MediaType.valueOf("application/*+xml")
//			, MediaType.MULTIPART_FORM_DATA
			);

	private static ThreadLocal<Long> requestBeginTime = new ThreadLocal<>();
	
	private static final Set<String> skipUrls = new HashSet<>(
			Arrays.asList("/actuator/**",
					"/favicon.ico",
					"/swagger-ui.html",
					"/v2/api-docs",
					"/webjars/springfox-swagger-ui/**",
					"/swagger-resources**",
					"/swagger-resources/configuration/**"
					));
	@Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
		return skipUrls.stream().anyMatch(p -> pathMatcher.match(p, request.getServletPath()));
    }
	
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		ThreadContext.put(CLINET_IP, getIPAddress(request));
		extractJwtToken(request);
		requestBeginTime.set(System.currentTimeMillis());
		doFilterWrapped(wrapRequest(request), wrapResponse(response), chain);
		ThreadContext.clearAll();
		MDC.clear();
	}

	// -[WRAPPER_REQUEST_RESPONSE]-[S]
	protected void doFilterWrapped(ContentCachingRequestWrapper request, ContentCachingResponseWrapper response,
			FilterChain filterChain) throws ServletException, IOException {
		try {
			RequestWrapper wrappedRequest = new RequestWrapper(request);
			ServletRequest servletRequest = wrappedRequest;
			
			ThreadContext.put("LOG_TYPE", "REQUEST");
			beforeRequest(request);

			ThreadContext.put("LOG_TYPE", "AUDIT");
			filterChain.doFilter(servletRequest, response);
			
		} finally {
			ThreadContext.put("LOG_TYPE", "RESPONSE");
			afterRequest(request, response);
			response.copyBodyToResponse();
		}
	}

	private static ContentCachingRequestWrapper wrapRequest(HttpServletRequest request) {
		if (request instanceof ContentCachingRequestWrapper) {
			return (ContentCachingRequestWrapper) request;
		} else {
			return new ContentCachingRequestWrapper(request);
		}
	}

	private static ContentCachingResponseWrapper wrapResponse(HttpServletResponse response) {
		if (response instanceof ContentCachingResponseWrapper) {
			return (ContentCachingResponseWrapper) response;
		} else {
			return new ContentCachingResponseWrapper(response);
		}
	}
	// -[WRAPPER_REQUEST_RESPONSE]-[E]

	// -[LOG_PATTERN_INFO]-[S]
	protected String getIPAddress(HttpServletRequest request) {
		String ipAddress = request.getHeader("X-Forwarded-For");
		if (null == ipAddress) {
			ipAddress = request.getRemoteAddr();
		}
		return ipAddress;
	}

	protected void extractJwtToken(HttpServletRequest request) {
		Object user_name = null;
		Object client_id = null;
		String tokenBearer = request.getHeader("authorization");
		if (null != tokenBearer) {
			String token = tokenBearer.replaceAll("(?i)bearer ", "");// OAuth2AccessToken.BEARER_TYPE
			Map<String, Object> map = JwtUtil.convertAccessToken(token);
			user_name = map.get("user_name");
			client_id = map.get("client_id");
		}

		ThreadContext.put(USER_NAME, (null == user_name) ? "" : String.valueOf(user_name));
		ThreadContext.put(OAUTH_CLIENT_ID, (null == client_id) ? "" : String.valueOf(client_id));
	}
	// -[LOG_PATTERN_INFO]-[E]

	// -[WRITE JSON LOG]-[S]
	protected void beforeRequest(ContentCachingRequestWrapper request) {
		JSONObject printOutObj = new JSONObject();
		try {
			printOutObj.accumulate("type", "REQUEST");
			printOutObj.accumulate("url", request.getRequestURL());
			printOutObj.accumulate("method", request.getMethod());
			printOutObj.accumulate("headers", logRequestHeader(request));
			printOutObj.accumulate("params", logRequestParam(request));
			printOutObj.accumulate("content-type", request.getContentType());
			printOutObj.accumulate("content", logRequestContent(request));
			logger.info(printOutObj.toString());
		} catch (JSONException e) {
			logger.error("beforeRequest JSONException : ", e);
		}
	}

	protected void afterRequest(ContentCachingRequestWrapper request, ContentCachingResponseWrapper response) {
			JSONObject printOutObj = new JSONObject();
			try {
				printOutObj.accumulate("type", "RESPONSE");
				printOutObj.accumulate("url", request.getRequestURL());
				printOutObj.accumulate("method", request.getMethod());
				printOutObj.accumulate("status", response.getStatus());
				printOutObj.accumulate("status-text", statusText(response.getStatus()));
				printOutObj.accumulate("headers", logResponseHeader(response));
				printOutObj.accumulate("content-type", response.getContentType());
				printOutObj.accumulate("content", logResponseContent(response));
				long duration = System.currentTimeMillis() - requestBeginTime.get();
				printOutObj.accumulate("executiontime-ms", duration);
				logger.info(printOutObj.toString());
			} catch (JSONException e) {
				logger.error("afterRequest JSONException : ", e);
			}
	}
	// -[WRITE JSON LOG]-[E]
	
	// -[LOG - REQUEST]-[S]
	// ALL Header
	// host|authorization|connection|cache-control|upgrade-insecure-requests|user-agent|sec-fetch-user|accept|sec-fetch-site|sec-fetch-mode|accept-encoding|accept-language
	private static final String PATTERN_REQUEST_HEADER_NAME = "^(host|user-agent|accept-language|referer|cookie|)$"; // user-agent,host,referer

	private String logRequestHeader(ContentCachingRequestWrapper request) {
		JSONObject headerObj = new JSONObject();
		Enumeration<String> headerNames = request.getHeaderNames();
		while (headerNames.hasMoreElements()) {
			String headerName = headerNames.nextElement();
			if (headerName.matches(PATTERN_REQUEST_HEADER_NAME)) {
				try {
					headerObj.accumulate(headerName, request.getHeader(headerName));
				} catch (JSONException e) {
					logger.error("logRequestHeader JSONException : ", e);
				}
			}
		}
		return headerObj.toString();
	}
	
	private String logRequestParam(ContentCachingRequestWrapper request) {
		JSONObject paramObj = new JSONObject();
		Enumeration<String> params = request.getParameterNames();
		while (params.hasMoreElements()) {
			String paramName = params.nextElement();
			try {
				paramObj.accumulate(paramName, request.getParameter(paramName));
			} catch (JSONException e) {
				logger.error("logRequestParam JSONException : ", e);
			}
		}
		return paramObj.toString();
	}
	
	private String logRequestContent(ContentCachingRequestWrapper request) {
		String contentString="";
		byte[] content = request.getContentAsByteArray();
		if (content.length > 0) {
			MediaType mediaType = MediaType.valueOf(request.getContentType());
			boolean visible = VISIBLE_TYPES.stream().anyMatch(visibleType -> visibleType.includes(mediaType));
			if (visible) {
				contentString = new String(content, StandardCharsets.UTF_8);
			}
		}
		return contentString;
	}
	// -[LOG - REQUEST]-[E]
	
	// -[LOG - RESPONSE]-[S]
	// ALL Response Header
	// access-control-allow-headers|access-control-allow-methods|access-control-max-age|content-disposition
	private String logResponseHeader(ContentCachingResponseWrapper response) {
		JSONObject headerObj = new JSONObject();
		response.getHeaderNames().forEach(headerName -> response.getHeaders(headerName).forEach(headerValue -> {
			try {
				headerObj.put(headerName, headerValue);
			} catch (JSONException e) {
				logger.error("logResponseHeader JSONException : ", e);
			}
		}));
		return headerObj.toString();
	}

	private String logResponseContent(ContentCachingResponseWrapper response) {
		String contentString="";
		byte[] content = response.getContentAsByteArray();
		if (content.length > 0) {
			MediaType mediaType = MediaType.valueOf(response.getContentType());
			boolean visible = VISIBLE_TYPES.stream().anyMatch(visibleType -> visibleType.includes(mediaType));
			if (visible) {
				contentString = new String(content, StandardCharsets.UTF_8);
			} 
		}
		return contentString;
	}
	// -[LOG - RESPONSE]-[E]
	
	private static String statusText(int code) {
		String statusText = "";
		try {
			statusText = HttpStatus.valueOf(code).name();
		}catch(IllegalArgumentException e){
			logger.error("statusText IllegalArgumentException code:{}",code);
		}
		return statusText;
	}
	
	public class RequestWrapper extends HttpServletRequestWrapper {
		
		private String _body;

		public RequestWrapper(HttpServletRequest request) throws IOException {
			super(request);
			_body = "";
			BufferedReader bufferedReader = request.getReader();			
			String line;
			while ((line = bufferedReader.readLine()) != null){
				_body += line;
			}
		}

		@Override
		public ServletInputStream getInputStream() throws IOException {
			final ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(_body.getBytes());
			return new ServletInputStream() {
				public int read() throws IOException {
					return byteArrayInputStream.read();
				}

				@Override
				public boolean isFinished() {
					return true;
				}

				@Override
				public boolean isReady() {
					return true;
				}

				@Override
				public void setReadListener(ReadListener listener) {
				}
			};
		}

		@Override
		public BufferedReader getReader() throws IOException {
			return new BufferedReader(new InputStreamReader(this.getInputStream()));
		}
	}
}
