package cz.metacentrum.perun.rpc.methods;

import cz.metacentrum.perun.core.api.exceptions.PerunException;
import cz.metacentrum.perun.rpc.ApiCaller;
import cz.metacentrum.perun.rpc.ManagerMethod;

import cz.metacentrum.perun.rpc.deserializer.Deserializer;
import java.util.Map;

public enum OIDCManagerMethod implements ManagerMethod {

	/*#
	 * Returns user information based on valid access_token.
	 *
	 * @param access_token String Access_token.
	 * @return Map<String, Object> User claims
	 */
	getUserByUserExtSource {

		@Override
		public Map<String, Object> call(ApiCaller ac, Deserializer parms) throws PerunException {
			return ac.getOidcManager().getUserInfo(ac.getSession(),
					parms.readString("access_token"));
		}
	}
}
