package cz.metacentrum.perun.core.entry;

import cz.metacentrum.perun.core.api.OIDCManager;
import cz.metacentrum.perun.core.api.PerunSession;
import cz.metacentrum.perun.core.api.exceptions.InternalErrorException;
import cz.metacentrum.perun.core.api.exceptions.UserNotExistsException;
import cz.metacentrum.perun.core.bl.OIDCManagerBl;
import cz.metacentrum.perun.core.bl.PerunBl;
import cz.metacentrum.perun.core.impl.Utils;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.json.JSONException;

import java.io.IOException;
import java.util.Map;

/**
 * Created on 24. 4. 2016.
 *
 * @author Oliver Mrázik
 */
public class OIDCManagerEntry implements OIDCManager {
	private PerunBl perunBl;
	private OIDCManagerBl oidcManagerBl;
	
	public OIDCManagerEntry(PerunBl perunBl) {
		this.perunBl = perunBl;
		this.oidcManagerBl = this.perunBl.getOidcManagerBl();
	}
	
	public OIDCManagerEntry() {
	}

	@Override
	public Map<String, Object> getUserInfo(PerunSession perunSession, String at) throws InternalErrorException, UserNotExistsException, InvalidJwtException, JSONException, IOException {
		Utils.notNull(perunSession, "perunSession");
		return oidcManagerBl.getUserInfo(perunSession, at);
	}

	public PerunBl getPerunBl() {
		return perunBl;
	}

	public void setPerunBl(PerunBl perunBl) {
		this.perunBl = perunBl;
	}

	public void setOidcManagerBl(OIDCManagerBl oidcManagerBl) {
		this.oidcManagerBl = oidcManagerBl;
	}
}
