package io.github.vadimv.servercomponents.oauth;

public class AuthException extends Exception {
    public AuthException(Throwable e) {
        super(e);
    }

    public AuthException(String s) {
        super(s);
    }

    public AuthException(String message, Throwable e) {
        super(message, e);
    }
}
