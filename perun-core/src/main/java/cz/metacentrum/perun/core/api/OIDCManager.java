package cz.metacentrum.perun.core.api;

import cz.metacentrum.perun.core.api.exceptions.InternalErrorException;
import cz.metacentrum.perun.core.api.exceptions.UserNotExistsException;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.lang.JoseException;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.io.InputStreamReader;

/**
 * Created on 24. 4. 2016.
 *
 * @author Oliver Mrázik
 */
public interface OIDCManager {

	/**
	 * Return claims about user based on received access_token. Token introspection is done internally.
	 * @param perunSession perun session
	 * @param at access_token
	 * @return JSON claims about user
	 *
	 * @throws InternalErrorException when something happens inside Perun while fetching user information
	 * @throws UserNotExistsException when user not exist for given id
	 * @throws JSONException while transforming String into {@link JSONObject}
	 * @throws InvalidJwtException when token is invalid
	 * @throws IOException while storing response from {@link InputStreamReader}
	 */
	String getUserInfo(PerunSession perunSession, String at) throws InternalErrorException, UserNotExistsException, InvalidJwtException, JSONException, IOException;

	/**
	 * 
	 * @return
	 */
	int validateToken(String at) throws JoseException, JSONException, MalformedClaimException, InvalidJwtException;
//	int introspectToken(String at) throws JoseException, JSONException, MalformedClaimException, InvalidJwtException;
}
