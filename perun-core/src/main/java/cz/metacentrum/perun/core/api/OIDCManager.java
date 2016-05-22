package cz.metacentrum.perun.core.api;

import cz.metacentrum.perun.core.api.exceptions.InternalErrorException;
import cz.metacentrum.perun.core.api.exceptions.InvalidTokenException;
import cz.metacentrum.perun.core.api.exceptions.UserNotExistsException;
import org.json.JSONObject;

import java.io.InputStreamReader;
import java.util.Map;

/**
 * OIDC manager entry layer interface.
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
	 * @throws InternalErrorException when something happens inside Perun while fetching user information or
	 * 	while transforming String into {@link JSONObject} or 
	 * 	while storing response from {@link InputStreamReader}
	 * @throws UserNotExistsException when user not exist for given id
	 * @throws InvalidTokenException when token is invalid
	 */
	Map<String, Object> getUserInfo(PerunSession perunSession, String at) throws InternalErrorException, UserNotExistsException, InvalidTokenException;
}
