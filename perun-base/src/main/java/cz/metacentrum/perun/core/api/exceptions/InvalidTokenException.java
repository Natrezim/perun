package cz.metacentrum.perun.core.api.exceptions;

/**
 * Checked version of InvalidTokenException.
 *
 * @author @author Oliver Mrázik
 */
public class InvalidTokenException extends PerunException {
	
	public InvalidTokenException(String message) {
		super(message);
	}

	public InvalidTokenException(String message, Throwable cause) {
		super(message, cause);
	}

	public InvalidTokenException(Throwable cause) {
		super(cause);
	}
}
