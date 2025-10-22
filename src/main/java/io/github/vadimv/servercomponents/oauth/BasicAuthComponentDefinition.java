package io.github.vadimv.servercomponents.oauth;

import rsp.component.*;
import rsp.component.definitions.StatefulComponentDefinition;
import rsp.component.definitions.lookup.AddressBarLookupComponentDefinition;
import rsp.server.http.HttpRequest;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.function.Supplier;

import static rsp.html.HtmlDsl.*;

/**
 * This class is for a wrapper component supporting for basic access authentication for a wrapped components tree.
 * @param <S> a type of the wrapped component's state
 */
public class BasicAuthComponentDefinition<S> extends StatefulComponentDefinition<BasicAuthComponentDefinition.AuthorizationState<S>> {
    private final System.Logger logger = System.getLogger(getClass().getName());
    private final HttpRequest httpRequest;
    private final Supplier<BasicCredentials> basicCredentialsSupplier;
    private final StatefulComponentDefinition<S> componentDefinition;

    public BasicAuthComponentDefinition(HttpRequest httpRequest,
                                        Supplier<BasicCredentials> basicCredentialsSupplier,
                                        StatefulComponentDefinition<S> componentDefinition) {
        super(AddressBarLookupComponentDefinition.class);
        this.httpRequest = Objects.requireNonNull(httpRequest);
        this.basicCredentialsSupplier = Objects.requireNonNull(basicCredentialsSupplier);
        this.componentDefinition = Objects.requireNonNull(componentDefinition);
    }

    @Override
    public ComponentStateSupplier<AuthorizationState<S>> stateSupplier() {
        try {
            final String user = authorizedUser(httpRequest);
            if (user != null) {
                logger.log(System.Logger.Level.DEBUG, "Basic access authentication: authorised");
                return (_, lookup)  -> {
                    lookup.put("user", user);
                    return new AuthorizationState.Authorized<>(componentDefinition.stateSupplier());
                };
            }
        } catch (AuthException e) {
            logger.log(System.Logger.Level.ERROR, "Basic access authentication error", e);
        }
        logger.log(System.Logger.Level.DEBUG, "Base authorization: not authorised");
        return (_, lookup) -> {
            lookup.remove("user");
            return new AuthorizationState.NotAuthorized<>();
        };
    }

    @Override
    public ComponentView<AuthorizationState<S>> componentView() {
        return _ -> authorizationState -> {
            if (authorizationState instanceof AuthorizationState.NotAuthorized<S>) {
                return html(
                        text("Not authorized")
                ).addHeaders(Map.of("WWW-Authenticate", "Basic realm=\"User Visible Realm\", charset=\"UTF-8\"" )).statusCode(401);
            } else {
                return componentDefinition;
            }

        };
    }

    private String authorizedUser(HttpRequest httpRequest) throws AuthException {
        final var authorizationHeader = httpRequest.header("Authorization");
        if (authorizationHeader.isPresent()) {
            final String authorizationHeaderValue = authorizationHeader.get();
            try {
                if (!authorizationHeaderValue.startsWith("Basic ")) {
                    throw new AuthException("Unexpected format of the Authorization header");
                }
                final byte[] decodedBytes = Base64.getDecoder().decode(authorizationHeaderValue.substring("Basic ".length()));
                final String decodedString = new String(decodedBytes, StandardCharsets.UTF_8);
                final String[] tokens = decodedString.split(":");
                if (tokens.length == 0) {
                    return null;
                }
                if (tokens.length > 2) {
                    throw new AuthException("Unexpected format of the Authorization header");
                }
                final BasicCredentials basicCredentials = basicCredentialsSupplier.get();
                if (tokens.length == 1 && decodedString.endsWith(":") && basicCredentials.userName.equals(tokens[0]) && basicCredentials.password.isEmpty()) {
                    return basicCredentials.userName;
                }
                if (tokens.length == 2 && basicCredentials.userName.equals(tokens[0]) && basicCredentials.password.equals(tokens[1])) {
                    return basicCredentials.userName;
                }
            } catch (Throwable e) {
                throw new AuthException("Error decoding Base64 authorization header", e);
            }
        }
        return null;
    }

    public record BasicCredentials(String userName, String password) {
        public BasicCredentials {
            Objects.requireNonNull(userName);
            Objects.requireNonNull(password);
        }
    }

    public sealed interface AuthorizationState<S> {
        record NotAuthorized<S>() implements AuthorizationState<S> {
        };

        record Authorized<S>(ComponentStateSupplier<S> wrappedState) implements AuthorizationState<S> {
        }
    }


}
