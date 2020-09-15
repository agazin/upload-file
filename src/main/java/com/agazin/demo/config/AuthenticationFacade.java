package com.agazin.demo.config;

import java.io.Serializable;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.stereotype.Component;
import org.springframework.util.ObjectUtils;

@Component
public class AuthenticationFacade implements Serializable {

	private static final long serialVersionUID = 1590403495252059713L;
	@Autowired
	private ResourceServerTokenServices tokenServices;

	public Authentication getAuthentication() {
		return SecurityContextHolder.getContext().getAuthentication();
	}

	public DataLoginModel getDataLogin() {

		DataLoginModel dataLoginModel = null;
		Authentication userAuthentication = getAuthentication();
		if (!ObjectUtils.isEmpty(userAuthentication.getDetails())
				&& (userAuthentication.getDetails() instanceof OAuth2AuthenticationDetails)) {
			OAuth2AuthenticationDetails oAuth2AuthenticationDetails = (OAuth2AuthenticationDetails) userAuthentication
					.getDetails();
			String jwtToken = oAuth2AuthenticationDetails.getTokenValue();
			if (!ObjectUtils.isEmpty(jwtToken)) {
				Map<String, Object> details = tokenServices.readAccessToken(oAuth2AuthenticationDetails.getTokenValue())
						.getAdditionalInformation();
				dataLoginModel = new DataLoginModel(details);
			}
		}
		return dataLoginModel;

	}

	public String getToken() {
		return (OAuth2AuthenticationDetails.class.cast(SecurityContextHolder.getContext().getAuthentication().getDetails())).getTokenValue();
	}

	public class DataLoginModel {
		// Common
		private static final String CLIENT_ID = "client_id";
		private static final String OAUTH_SESSION_ID = "session_id";
		private static final String OAUTH_ACCESS_CHANNAL_CODE = "access_channel_code";
		private static final String OAUTH_ACCESS_CHANNAL_NAME = "access_channel_name";
		private static final String OAUTH_JTI = "jti";
		private static final String OAUTH_USER_NAME = "user_name";
		
		// Staff
		private static final String STAFF_OAUTH_OFFICE_ID = "office_id";
		private static final String STAFF_USER_ID = "uid";
		
		// User
		private static final String USER_ID = "1";
		private static final String USER_NID = "2";
		private static final String USER_TIN = "3";
		private static final String USER_CHANNEL = "channel";
				
		// Common
		private String clientId;
		private String sessionId;
		private String accessChannelCode;
		private String accessChannelName;
		private String jti;
		private String userId;
		private String userName;
		private String channel;

		// Staff
		private String officeId;

		// User
		private String nid;
		private String tin;

		DataLoginModel(Map<String, Object> details) {
			// Common
			this.clientId = ObjectUtils.nullSafeToString(details.get(CLIENT_ID));
			this.sessionId = ObjectUtils.nullSafeToString(details.get(OAUTH_SESSION_ID));
			this.accessChannelCode = ObjectUtils.nullSafeToString(details.get(OAUTH_ACCESS_CHANNAL_CODE));
			this.accessChannelName = ObjectUtils.nullSafeToString(details.get(OAUTH_ACCESS_CHANNAL_NAME));
			this.jti = ObjectUtils.nullSafeToString(details.get(OAUTH_JTI));
			this.userName = ObjectUtils.nullSafeToString(details.get(OAUTH_USER_NAME));
			this.userId = (details.get(STAFF_USER_ID) != null)? ObjectUtils.nullSafeToString(details.get(STAFF_USER_ID)): ObjectUtils.nullSafeToString(details.get(USER_ID));
			this.channel = ObjectUtils.nullSafeToString(details.get(USER_CHANNEL));

			// Staff
			this.officeId = ObjectUtils.nullSafeToString(details.get(STAFF_OAUTH_OFFICE_ID));
			
			// User
			this.nid = ObjectUtils.nullSafeToString(details.get(USER_NID));
			this.tin = ObjectUtils.nullSafeToString(details.get(USER_TIN));
		}

		public String getSessionId() {
			return sessionId;
		}

		public void setSessionId(String sessionId) {
			this.sessionId = sessionId;
		}

		public String getAccessChannelCode() {
			return accessChannelCode;
		}

		public void setAccessChannelCode(String accessChannelCode) {
			this.accessChannelCode = accessChannelCode;
		}

		public String getAccessChannelName() {
			return accessChannelName;
		}

		public void setAccessChannelName(String accessChannelName) {
			this.accessChannelName = accessChannelName;
		}

		public String getOfficeId() {
			return officeId;
		}

		public void setOfficeId(String officeId) {
			this.officeId = officeId;
		}

		public String getJti() {
			return jti;
		}

		public void setJti(String jti) {
			this.jti = jti;
		}

		public String getUserId() {
			return userId;
		}

		public void setUserId(String userId) {
			this.userId = userId;
		}

		public String getUserName() {
			return userName;
		}

		public void setUserName(String userName) {
			this.userName = userName;
		}
		
		public String getChannel() {
			return channel;
		}

		public void setChannel(String channel) {
			this.channel = channel;
		}

		public String getNid() {
			return nid;
		}

		public void setNid(String nid) {
			this.nid = nid;
		}

		public String getTin() {
			return tin;
		}

		public void setTin(String tin) {
			this.tin = tin;
		}

		public String getClientId() {
			return clientId;
		}

		public void setClientId(String clientId) {
			this.clientId = clientId;
		}
	}
}