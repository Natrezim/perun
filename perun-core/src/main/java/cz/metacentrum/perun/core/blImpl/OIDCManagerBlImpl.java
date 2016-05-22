package cz.metacentrum.perun.core.blImpl;

import cz.metacentrum.perun.core.api.Attribute;
import cz.metacentrum.perun.core.api.BeansUtils;
import cz.metacentrum.perun.core.api.PerunSession;
import cz.metacentrum.perun.core.api.User;
import cz.metacentrum.perun.core.api.exceptions.InternalErrorException;
import cz.metacentrum.perun.core.api.exceptions.InvalidTokenException;
import cz.metacentrum.perun.core.api.exceptions.UserNotExistsException;
import cz.metacentrum.perun.core.bl.OIDCManagerBl;
import cz.metacentrum.perun.core.bl.PerunBl;
import org.apache.commons.codec.binary.Base64;
import org.codehaus.jackson.JsonFactory;
import org.codehaus.jackson.JsonParser;
import org.codehaus.jackson.annotate.JsonIgnore;
import org.codehaus.jackson.map.ObjectMapper;

import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLConnection;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * OIDC manager business logic implementation.
 *
 * @author Oliver Mrázik
 */
public class OIDCManagerBlImpl implements OIDCManagerBl {
	
	private final static Logger log = LoggerFactory.getLogger(OIDCManagerBlImpl.class);

	private static final String DISCOVERY_URL = "https://perun-dev.meta.zcu.cz/oic-manager/.well-known/openid-configuration";

	private PerunBl perunBl;
	
	private JSONObject discoveryDocument;
	
	public OIDCManagerBlImpl() throws InternalErrorException {
		// load a discovery document
		fetchDiscoveryDocument();
	}

	@Override
	public Map<String, Object> getUserInfo(PerunSession perunSession, String at) throws UserNotExistsException, InternalErrorException, InvalidTokenException {
		log.debug("Starting userinfo flow.");
		Map<String, Object> userinfo = new HashMap<>();
		
		// validate token
		IntrospectionResponse response = introspectToken(at);
		if (response == null) {
			throw new InvalidTokenException("No response from introspection endpoint");
		}
		List<String> scopes = response.getScope();
		log.debug("Requested scopes: ['{}']", scopes);
				
		User user = perunBl.getUsersManagerBl().getUserById(perunSession, response.getSub());
		List<Attribute> attributes = perunBl.getAttributesManagerBl().getAttributes(perunSession, user);
		
		for (Attribute a : attributes) {
			if (a.getValue().equals("null")) continue;
			if (a.getFriendlyName().equals("id") && scopes.contains("openid")) {
				userinfo.put("sub", a.getValue());

			} else if (a.getFriendlyName().equals("displayName") && scopes.contains("profile")) {
				userinfo.put("name", a.getValue());

			} else if (a.getFriendlyName().equals("firstName") && scopes.contains("profile")) {
				userinfo.put("given_name", a.getValue());

			} else if (a.getFriendlyName().equals("lastName") && scopes.contains("profile")) {
				userinfo.put("family_name", a.getValue());

			} else if (a.getFriendlyName().equals("middleName") && scopes.contains("profile")) {
				userinfo.put("middle_name", a.getValue());

			} else if (a.getFriendlyName().equals("preferredMail") && scopes.contains("email")) {
				userinfo.put("email", a.getValue());
				userinfo.put("email_verified", true);

			} else if (a.getFriendlyName().equals("timezone") && scopes.contains("profile")) {
				userinfo.put("zoneinfo", a.getValue());
				
			} else if (a.getFriendlyName().equals("preferredLanguage") && scopes.contains("profile")) {
				userinfo.put("locale", a.getValue());

			}
		}
		
		log.debug("Userinfo flow finished. JSON returned");
		return userinfo;
	}

	/**
	 * Validates access_token against introspection endpoint on OIDC server.
	 * @param at validated access_token
	 * @return Part of a response stored in {@link IntrospectionResponse} object
	 * 
	 * @throws InternalErrorException while storing response from {@link InputStreamReader} or 
	 * while transforming String into {@link JSONObject}
	 * @throws InvalidTokenException when token is invalid
	 */
	private IntrospectionResponse introspectToken(String at) throws InternalErrorException, InvalidTokenException {

		URL introspectionEndpoint;
		IntrospectionResponse response;
		try {
			introspectionEndpoint = new URL(discoveryDocument.getString("introspection_endpoint") + "?token=" + at);
		
			URLConnection urlConnection = introspectionEndpoint.openConnection();
			
	//		======================================== CLIENT SECRET =========================================================
			String client_id = BeansUtils.getPropertyFromCustomConfiguration("oidc-clients.properties", "test.client_id");
			String client_secret = BeansUtils.getPropertyFromCustomConfiguration("oidc-clients.properties", "test.secret");
			
			String enc = client_id + ":" + client_secret;
			enc = Base64.encodeBase64String(enc.getBytes());
			// java bug
			enc = enc.replaceAll("\n", "");
	//		================================================================================================================
			
			urlConnection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
			urlConnection.setRequestProperty("Authorization", "Basic " + enc);
			InputStream is = urlConnection.getInputStream();
			InputStreamReader isr = new InputStreamReader(is);
	
			JsonFactory f = new JsonFactory();
			JsonParser jp = f.createJsonParser(isr);
			jp.configure(JsonParser.Feature.AUTO_CLOSE_SOURCE, true);
			
			ObjectMapper mapper = new ObjectMapper();
			response = mapper.readValue(jp, IntrospectionResponse.class);
	
			// parse and validate token
			if (!response.isActive()) {
				log.error("Token is not valid.");
				throw new InvalidTokenException("Token in not valid.");
			}
			if (!response.getScope().contains("openid")) {
				log.error("Openid scope is missing.");
				throw new InvalidTokenException("Openid scope is missing.");
			}
			if (!response.getClient_id().equals(client_id)) {
				log.error("Client_ids do not match.");
				throw new InvalidTokenException("Client_ids do not match.");
			}
			if (response.getSub() <= 0) {
				log.error("Invalid sub.");
				throw new InvalidTokenException("Invalid sub.");
			}
			
		} catch (JSONException | IOException e) {
			throw new InternalErrorException(e);
		}

		log.debug("Token is valid.");
		return response;
	}

	/**
	 * Fetch the discovery document from OIDC server and store it inside the manager.
	 * 
	 * @throws InternalErrorException while transforming String into {@link JSONObject} or while storing 
	 * response from {@link InputStreamReader}
	 */
	private void fetchDiscoveryDocument() throws InternalErrorException {
		URL url;
		try {
			url = new URL(DISCOVERY_URL);
		
			URLConnection urlConnection = url.openConnection();
			
			InputStream is = urlConnection.getInputStream();
			InputStreamReader isr = new InputStreamReader(is);
	
			int numCharsRead;
			char[] charArray = new char[1024];
			StringBuilder sb = new StringBuilder(2048);
			while ((numCharsRead = isr.read(charArray)) > 0) {
				sb.append(charArray, 0, numCharsRead);
			}

			discoveryDocument = new JSONObject(sb.toString());
			log.debug("Successfully obtained discovery document.");
		} catch (IOException | JSONException e) {
			throw new InternalErrorException(e);
		}
	}
	
	public void setPerunBl(PerunBl perunBl) {
		this.perunBl = perunBl;
	}

	public PerunBl getPerunBl() {
		return perunBl;
	}

	/**
	 * Private class for handling the response of an introspection.
	 */
	private static class IntrospectionResponse {
		private boolean active;
		private List<String> scope;
		@JsonIgnore
		private String expires_at;
		@JsonIgnore
		private int exp;
		private int sub;
		@JsonIgnore
		private String user_id;
		private String client_id;
		@JsonIgnore
		private String token_type;

		public IntrospectionResponse() {
		}

		public IntrospectionResponse(boolean active, List<String> scope, int sub, String client_id) {
			this.active = active;
			this.scope = scope;
			this.sub = sub;
			this.client_id = client_id;
		}

		public boolean isActive() {
			return active;
		}

		public void setActive(boolean active) {
			this.active = active;
		}

		public List<String> getScope() {
			return scope;
		}

		/**
		 * Takes string of scopes separated by spaces ' '.
		 * @param scope string containing scopes
		 */
		public void setScope(String scope) {
			this.scope = Arrays.asList(scope.split(" "));
		}

		public int getSub() {
			return sub;
		}

		public void setSub(int sub) {
			this.sub = sub;
		}

		public String getClient_id() {
			return client_id;
		}

		public void setClient_id(String client_id) {
			this.client_id = client_id;
		}
	}	
}