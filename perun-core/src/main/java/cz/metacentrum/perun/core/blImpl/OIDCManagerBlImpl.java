package cz.metacentrum.perun.core.blImpl;

import cz.metacentrum.perun.core.api.Attribute;
import cz.metacentrum.perun.core.api.PerunSession;
import cz.metacentrum.perun.core.api.User;
import cz.metacentrum.perun.core.api.exceptions.InternalErrorException;
import cz.metacentrum.perun.core.api.exceptions.UserNotExistsException;
import cz.metacentrum.perun.core.bl.OIDCManagerBl;
import cz.metacentrum.perun.core.bl.PerunBl;
import org.apache.commons.codec.binary.Base64;
import org.codehaus.jackson.JsonFactory;
import org.codehaus.jackson.JsonParser;
import org.codehaus.jackson.map.ObjectMapper;
import org.jose4j.jwk.JsonWebKey;

import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.lang.JoseException;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLConnection;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Created on 24. 4. 2016.
 *
 * @author Oliver Mrázik
 */
public class OIDCManagerBlImpl implements OIDCManagerBl {

	private final static Logger log = LoggerFactory.getLogger(OIDCManagerBlImpl.class);

	public static final String DISCOVERY_URL = "https://perun-dev.meta.zcu.cz/oic-manager/.well-known/openid-configuration";
	
	private static final String DISCOVERY_DOCUMENT_MOCK = "{\"request_parameter_supported\":true,\"id_token_encryption_alg_values_supported\":[\"RSA-OAEP\",\"RSA1_5\",\"RSA-OAEP-256\"],\"registration_endpoint\":\"https://perun-dev.meta.zcu.cz/oic-manager/register\",\"userinfo_signing_alg_values_supported\":[\"HS256\",\"HS384\",\"HS512\",\"RS256\",\"RS384\",\"RS512\",\"ES256\",\"ES384\",\"ES512\",\"PS256\",\"PS384\",\"PS512\"],\"token_endpoint\":\"https://perun-dev.meta.zcu.cz/oic-manager/token\",\"request_uri_parameter_supported\":false,\"request_object_encryption_enc_values_supported\":[\"A192CBC-HS384\",\"A256CBC+HS512\",\"A192GCM\",\"A128CBC+HS256\",\"A256CBC-HS512\",\"A256GCM\",\"A128GCM\",\"A128CBC-HS256\"],\"token_endpoint_auth_methods_supported\":[\"client_secret_post\",\"client_secret_basic\",\"client_secret_jwt\",\"private_key_jwt\",\"none\"],\"userinfo_encryption_alg_values_supported\":[\"RSA-OAEP\",\"RSA1_5\",\"RSA-OAEP-256\"],\"subject_types_supported\":[\"public\",\"pairwise\"],\"id_token_encryption_enc_values_supported\":[\"A192CBC-HS384\",\"A256CBC+HS512\",\"A192GCM\",\"A128CBC+HS256\",\"A256CBC-HS512\",\"A256GCM\",\"A128GCM\",\"A128CBC-HS256\"],\"claims_parameter_supported\":false,\"jwks_uri\":\"https://perun-dev.meta.zcu.cz/oic-manager/jwk\",\"id_token_signing_alg_values_supported\":[\"HS256\",\"HS384\",\"HS512\",\"RS256\",\"RS384\",\"RS512\",\"ES256\",\"ES384\",\"ES512\",\"PS256\",\"PS384\",\"PS512\",\"none\"],\"authorization_endpoint\":\"https://perun-dev.meta.zcu.cz/oic-manager/authorize\",\"require_request_uri_registration\":false,\"introspection_endpoint\":\"https://perun-dev.meta.zcu.cz/oic-manager/introspect\",\"request_object_encryption_alg_values_supported\":[\"RSA-OAEP\",\"RSA1_5\",\"RSA-OAEP-256\"],\"service_documentation\":\"https://perun-dev.meta.zcu.cz/oic-manager/about\",\"response_types_supported\":[\"code\",\"token\"],\"token_endpoint_auth_signing_alg_values_supported\":[\"HS256\",\"HS384\",\"HS512\",\"RS256\",\"RS384\",\"RS512\",\"ES256\",\"ES384\",\"ES512\",\"PS256\",\"PS384\",\"PS512\"],\"revocation_endpoint\":\"https://perun-dev.meta.zcu.cz/oic-manager/revoke\",\"request_object_signing_alg_values_supported\":[\"HS256\",\"HS384\",\"HS512\",\"RS256\",\"RS384\",\"RS512\",\"ES256\",\"ES384\",\"ES512\",\"PS256\",\"PS384\",\"PS512\"],\"claim_types_supported\":[\"normal\"],\"grant_types_supported\":[\"authorization_code\",\"implicit\",\"urn:ietf:params:oauth:grant-type:jwt-bearer\",\"client_credentials\",\"urn:ietf:params:oauth:grant_type:redelegate\"],\"scopes_supported\":[\"openid\",\"profile\",\"email\",\"address\",\"phone\",\"offline_access\"],\"userinfo_endpoint\":\"https://perun-dev.meta.zcu.cz/oic-manager/userinfo\",\"userinfo_encryption_enc_values_supported\":[\"A192CBC-HS384\",\"A256CBC+HS512\",\"A192GCM\",\"A128CBC+HS256\",\"A256CBC-HS512\",\"A256GCM\",\"A128GCM\",\"A128CBC-HS256\"],\"op_tos_uri\":\"https://perun-dev.meta.zcu.cz/oic-manager/about\",\"issuer\":\"https://perun-dev.meta.zcu.cz/oic-manager/\",\"op_policy_uri\":\"https://perun-dev.meta.zcu.cz/oic-manager/about\",\"claims_supported\":[\"sub\",\"name\",\"preferred_username\",\"given_name\",\"family_name\",\"middle_name\",\"nickname\",\"profile\",\"picture\",\"website\",\"gender\",\"zoneinfo\",\"locale\",\"updated_at\",\"birthdate\",\"email\",\"email_verified\",\"phone_number\",\"phone_number_verified\",\"address\"]}";

	private PerunBl perunBl;
	
	private JSONObject discoveryDocument;
	
	public OIDCManagerBlImpl() {
	}

	@Override
	public String getUserInfo(PerunSession perunSession, String at) throws JSONException, InvalidJwtException, IOException, UserNotExistsException, InternalErrorException {
		Map<String, Object> userinfo = new HashMap<>();
		
		// validate token
		IntrospectionResponse response = introspectToken(at);
		List<String> scopes = response.getScopes();
				
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

			} else if (a.getFriendlyName().equals("eduPersonPrincipalNames") && scopes.contains("profile")) {
				if (Objects.equals(a.getType(), "java.util.ArrayList") && a.getValue() instanceof ArrayList) {
					userinfo.put("preffered_username", ((ArrayList) a.getValue()).get(0));
				}

			} else if (a.getFriendlyName().equals("preferredMail") && scopes.contains("email")) {
				userinfo.put("email", a.getValue());
				userinfo.put("email_verified", true);

			} else if (a.getFriendlyName().equals("timezone") && scopes.contains("profile")) {
				userinfo.put("zoneinfo", a.getValue());

			} else if (a.getFriendlyName().equals("phone") && scopes.contains("phone")) {
				userinfo.put("phone_number", a.getValue());
				userinfo.put("phone_number_verified", true);

			} else if (a.getFriendlyName().equals("preferredLanguage") && scopes.contains("profile")) {
				userinfo.put("locale", a.getValue());

			}
		}
		
		JSONObject json = new JSONObject(userinfo);
		
		return json.toString();
	}

	
	
	@Override
	public int validateToken(String at) throws JoseException, JSONException, InvalidJwtException, MalformedClaimException {
		// A JSON Web Key (JWK) is a JavaScript Object Notation (JSON) data structure that represents a
		// cryptographic key (often but not always a public key). A JSON Web Key Set (JWK Set) document
		// is a JSON data structure for representing one or more JSON Web Keys (JWK). A JWK Set might,
		// for example, be obtained from an HTTPS endpoint controlled by the signer but this example
		// presumes the JWK Set JSONhas already been acquired by some secure/trusted means.
		// TODO: obtain from discovery document
		String jsonWebKeySetJson = "{" +
				"\"alg\":\"RSA256\"," +
				"\"e\":\"AQAB\"," +
				"\"kty\":\"RSA\"," +
				"\"kid\":\"perun\"" +
				"\"n\":\"iHmFhDaMkPXwyOZoF7C5NYnicXSDdwuo-Av2ZJ74fHqrrtFysv6FT2qAOu9YvBzyCJCWjIOPkanIBv1sLR9zKa93RGiSTEUuasJXAg7Qf4zUHArGIrkuWagFTJWXNQlwTISLsINNZtHs1hYuAAi81jDe_TEf0t_3dgTtsKcNElIgy3GpS00WafggmcmIYUE5Dh0fWDqFltaxvXQ_a76-RaQ9dw2qKSxEC2ABjwFYixH_AvZkjBj7Utlx9NGWg4VheZAFJduDpveMNIUnqa5MIisER0Hb0F8klKBJsYdmPHxgzFkfyoHI6v42saGlGjefV4OnvMLZka8JhgJyR6zcuQ\"," +
				"}";
		
		// Create jwk object
		JsonWebKey jwk = JsonWebKey.Factory.newJwk(jsonWebKeySetJson);

		// Use JwtConsumerBuilder to construct an appropriate JwtConsumer, which will
		// be used to validate and process the JWT.
		// The specific validation requirements for a JWT are context dependent, however,
		// it typically advisable to require a expiration time, a trusted issuer, and
		// and audience that identifies your system as the intended recipient.
		// If the JWT is encrypted too, you need only provide a decryption key or
		// decryption key resolver to the builder.
		JwtConsumer jwtConsumer = new JwtConsumerBuilder()
				.setRequireExpirationTime() // the JWT must have an expiration time
				.setAllowedClockSkewInSeconds(30) // allow some leeway in validating time based claims to account for clock skew
				.setRequireSubject() // the JWT must have a subject claim
				// TODO: get it from discovery document
				.setExpectedIssuer("https://perun-dev.meta.zcu.cz/oic-manager/") // whom the JWT needs to have been issued by
//				.setExpectedAudience("Audience") // to whom the JWT is intended for
				.setVerificationKey(jwk.getKey()) // verify the signature with the public key
				.build(); // create the JwtConsumer instance

		//  Validate the JWT and process it to the Claims
		JwtClaims jwtClaims = jwtConsumer.processToClaims(at);
		
		// do the token validation?
		log.debug(jwtClaims.toJson());
		
		return Integer.parseInt(jwtClaims.getSubject());
	}

	/**
	 * Validates access_token against introspection endpoint on OIDC server.
	 * @param at validated access_token
	 * @return Part of a response stored in {@link IntrospectionResponse} object
	 * 
	 * @throws IOException while storing response from {@link InputStreamReader} 
	 * @throws JSONException while transforming String into {@link JSONObject}
	 * @throws InvalidJwtException when token is invalid
	 */
	private IntrospectionResponse introspectToken(String at) throws IOException, JSONException, InvalidJwtException {
		
		// get the discovery document
		fetchDiscoveryDocument();
		
//		List<String> scopes = new ArrayList<>();

//		================================================================================================================
//		MOCK THE DISCOVERY DOCUMENT
		discoveryDocument = new JSONObject(DISCOVERY_DOCUMENT_MOCK);
//		================================================================================================================

		log.debug("Hi reader. I am before introspect endpoint.");
		URL introspectionEndpoint = new URL(discoveryDocument.getString("introspection_endpoint") + "token=" + at);
		URLConnection urlConnection = introspectionEndpoint.openConnection();
		
//		============================================================================================================
//		CLIENT SECRET
		String client_id = "test-page";
		String client_secret = "tajnasprava";
		String enc = client_id + ":" + client_secret;
		enc = Base64.encodeBase64String(enc.getBytes());
//			============================================================================================================
		
		
		urlConnection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
		urlConnection.setRequestProperty("Authorization", "Basic " + enc);
		InputStream is = urlConnection.getInputStream();
		InputStreamReader isr = new InputStreamReader(is);

		JsonFactory f = new JsonFactory();
		JsonParser jp = f.createJsonParser(isr);
		jp.configure(JsonParser.Feature.AUTO_CLOSE_SOURCE, true);

		ObjectMapper mapper = new ObjectMapper();
		IntrospectionResponse response = mapper.readValue(jp, IntrospectionResponse.class);
		
//		// return JsonToken.START_OBJECT
//		jp.nextToken();
//		while (jp.nextToken() != JsonToken.END_OBJECT) {
//			String fieldName = jp.getCurrentName();
//			jp.nextToken(); // move to value
//			// active
//			if (fieldName.equals("active")) {
//				response.setActive(jp.getBooleanValue());
//				if (!response.isActive()) {
//					throw new InvalidJwtException("Token in not valid.");
//				}
//			}
//			// scopes
//			if (fieldName.equals("scope")) {
//				String tokenScope = jp.getText();
//				scopes = Arrays.asList(tokenScope.split(" "));
//				if (!scopes.contains("openid")) {
//					throw new InvalidJwtException("Openid scope is missing.");
//				}
//			}
//			// client_id
//			if (fieldName.equals("client_id")) {
//				String cid = jp.getText();
//				if (!cid.equals(client_id)) {
//					throw new InvalidJwtException("Client_ids do not match.");
//				}
//			}
//			// sub
//			if (fieldName.equals("sub")) {
//				int sub = jp.getIntValue();
//				if (sub <= 0) {
//					throw new InvalidJwtException("Invalid sub.");
//				}
//			}
//			
//		}	

		if (!response.isActive()) {
			throw new InvalidJwtException("Token in not valid.");
		}
		if (!response.getScopes().contains("openid")) {
			throw new InvalidJwtException("Openid scope is missing.");
		}
		if (!response.getClient_id().equals(client_id)) {
			throw new InvalidJwtException("Client_ids do not match.");
		}
		if (response.getSub() <= 0) {
			throw new InvalidJwtException("Invalid sub.");
		}
		
		return response;
	}

	/**
	 * Fetch the discovery document from OIDC server and store it inside the manager.
	 * 
	 * @throws JSONException while transforming String into {@link JSONObject}
	 * @throws IOException while storing response from {@link InputStreamReader} 
	 */
	private void fetchDiscoveryDocument() throws JSONException, IOException {
		log.debug("Hi reader. I am at fetch document method.");
//		CookieHandler.setDefault(new CookieManager());
		URL url = new URL(DISCOVERY_URL);
		URLConnection urlConnection = url.openConnection();

		// it should be without credentials
//			urlConnection.setRequestProperty("Authorization", "Basic bmF0cmV6aW06TkB0cmV6MU0=");
		InputStream is = urlConnection.getInputStream();
		InputStreamReader isr = new InputStreamReader(is);

		int numCharsRead;
		char[] charArray = new char[1024];
		StringBuilder sb = new StringBuilder(2048);
		while ((numCharsRead = isr.read(charArray)) > 0) {
			sb.append(charArray, 0, numCharsRead);
		}

		// TODO remove log
		log.debug("DISCOVERY DOCUMENT = " + sb.toString());

		discoveryDocument = new JSONObject(sb.toString());
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
		private List<String> scopes;
		private int sub;
		private String client_id;

		public IntrospectionResponse() {
		}

		public IntrospectionResponse(boolean active, List<String> scopes, int sub, String client_id) {
			this.active = active;
			this.scopes = scopes;
			this.sub = sub;
			this.client_id = client_id;
		}

		public boolean isActive() {
			return active;
		}

		public void setActive(boolean active) {
			this.active = active;
		}

		public List<String> getScopes() {
			return scopes;
		}

		/**
		 * Takes string of scopes separated by spaces ' '.
		 * @param scopes string containing scopes
		 */
		public void setScopes(String scopes) {
			this.scopes = Arrays.asList(scopes.split(" "));
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