package io.github.vadimv.servercomponents.oauth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import rsp.component.ComponentStateSupplier;
import rsp.component.ComponentView;
import rsp.component.definitions.StatefulComponentDefinition;
import rsp.component.definitions.lookup.AddressBarLookupComponentDefinition;
import rsp.server.http.HttpRequest;
import rsp.server.http.RelativeUrl;
import rsp.util.json.JsonDataType;
import rsp.util.json.JsonSimpleUtils;

import java.io.IOException;
import java.net.URI;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import static rsp.html.HtmlDsl.*;

/**
 * This class is for a wrapper component supporting for OAuth 2.0 PKCE Flow for a wrapped components tree.
 * @param <O> a type of the wrapped component's state
 */
public class OAuthPKCEComponentDefinition<O, P> extends StatefulComponentDefinition<OAuthPKCEComponentDefinition.AuthorizationState> {
    private static final Logger log = LoggerFactory.getLogger(OAuthPKCEComponentDefinition.class);
    private final System.Logger logger = System.getLogger(getClass().getName());
    private final HttpRequest httpRequest;
    private final String protectedPath;
    private final StatefulComponentDefinition<O> protectedComponentDefinition;
    private final StatefulComponentDefinition<P> openComponentDefinition;
    private static final Map<String, String> authorizedSessions = new ConcurrentHashMap<>();
    private static final Map<String, RelativeUrl> unauthorizedURLs = new ConcurrentHashMap<>();
    private static final Map<String, SessionAuthorization> statesCodeVerifiers = new ConcurrentHashMap<>();

    public OAuthPKCEComponentDefinition(HttpRequest httpRequest,
                                        String protectedPath,
                                        StatefulComponentDefinition<O> protectedComponentDefinition,
                                        StatefulComponentDefinition<P> openComponentDefinition) {
        super(AddressBarLookupComponentDefinition.class);
        this.httpRequest = Objects.requireNonNull(httpRequest);
        this.protectedPath = protectedPath;

        this.protectedComponentDefinition = Objects.requireNonNull(protectedComponentDefinition);
        this.openComponentDefinition = Objects.requireNonNull(openComponentDefinition);
    }

    @Override
    public ComponentStateSupplier<AuthorizationState> stateSupplier() {
        try {
            if (httpRequest.path.startsWith("logout")) {
                logger.log(System.Logger.Level.DEBUG, "Logout: " + httpRequest.deviceId());
                if (httpRequest.deviceId().isPresent()) {
                    authorizedSessions.remove(httpRequest.deviceId().get());
                }
                return (_, lookup)  -> {
                    lookup.remove("user");
                    return new AuthorizationState.Redirect("/");
                };
            } else if (httpRequest.path.startsWith(protectedPath)
                    && httpRequest.deviceId().isPresent()
                    && authorizedSessions.containsKey(httpRequest.deviceId().get())) {
                logger.log(System.Logger.Level.DEBUG, "Accessing the protected path with an authorised device session: " + httpRequest.deviceId());
                return (_, lookup)  -> {
                    lookup.put("user", "user1");
                    return new AuthorizationState.Authorized<>();
                };
            } else if (httpRequest.path.startsWith(protectedPath)) {
                logger.log(System.Logger.Level.DEBUG, "Trying to access the protected path, redirecting to the login page");
                return (_, lookup)  -> {
                    final String sessionId = (String) lookup.get("sessionId");
                    final String deviceId = (String) lookup.get("deviceId");
                    unauthorizedURLs.put(deviceId, httpRequest.relativeUrl());

                    return new AuthorizationState.Redirect("/login.html");
                };
            } else if  (httpRequest.deviceId().isPresent() && httpRequest.path.startsWith("login")) {
                logger.log(System.Logger.Level.DEBUG, "Staring OAuth 2 PKCE flow..");

                // 1. Create a Code Verifier and Challenge
                final String codeVerifier = generateRandomString(64);
                final String codeChallenge;
                try {
                    codeChallenge = generateCodeChallange(codeVerifier);
                } catch (UnsupportedEncodingException | NoSuchAlgorithmException e) {
                    throw new AuthException(e);
                }

                // 2. Build the Authorization URL
                final String state = generateRandomString(16);
                final String authorizationURL = "http://localhost:8080/default/authorize?" +
                        "response_type=code" +
                        "&client_id=4aw6ppymEN7zxUVJL9wB1WSc" +
                        "&redirect_uri=http://localhost:8085/callback" +
                        "&scope=openid%20profile%20email" +
                        "&state=" + state +
                        "&code_challenge=" + codeChallenge +
                        "&code_challenge_method=S256";

                statesCodeVerifiers.put(state, new SessionAuthorization(httpRequest.deviceId().get(), codeVerifier));
                return (_, lookup)  -> {
                    return new AuthorizationState.Redirect(authorizationURL);
                };
            } else if (httpRequest.path.startsWith("callback")) {
                logger.log(System.Logger.Level.DEBUG, "Callback URL hit");
                final Optional<String> stateQueryParameterValue = httpRequest.queryParameters.parameterValue("state");
                final Optional<String> codeQueryParameterValue = httpRequest.queryParameters.parameterValue("code");
                if (stateQueryParameterValue.isPresent() && codeQueryParameterValue.isPresent()) {

                    // 3. Verify the state parameter
                    final SessionAuthorization codeVerifier = statesCodeVerifiers.remove(stateQueryParameterValue.get());
                    if (codeVerifier == null) {
                        throw new AuthException("Unmatched state query parameter");
                    }

                    // 4. Exchange the Authorization Code
                    // build a POST request to the token endpoint
                    final String tokenRequestURL = "http://localhost:8080/default/token";
                    final String tokenRequestQueryParametersString =
                            "grant_type=authorization_code" +
                            "&client_id=4aw6ppymEN7zxUVJL9wB1WSc" +
                            "&client_secret=BfoMogOMp9ZFenyvQhNU5OE-F9iv9ONr8yKByo8VKw1uFtKH" +
                            "&redirect_uri=http://localhost:8085/callback" +
                            "&code=" + codeQueryParameterValue +
                            "&code_verifier=" + codeVerifier.codeVerifier;

                    final java.net.http.HttpRequest tokenRequest = java.net.http.HttpRequest.newBuilder()
                            .uri(URI.create(tokenRequestURL))
                            .header("Content-Type", "application/x-www-form-urlencoded")
                            .POST(java.net.http.HttpRequest.BodyPublishers.ofString(tokenRequestQueryParametersString))
                            .build();
                    final java.net.http.HttpResponse<String> response;
                    try (java.net.http.HttpClient httpClient = java.net.http.HttpClient.newHttpClient()) {
                        try {
                            response = httpClient.send(tokenRequest, java.net.http.HttpResponse.BodyHandlers.ofString());
                        } catch (IOException | InterruptedException e) {
                            throw new AuthException("An error occurred while requesting a token at:" + tokenRequestURL, e);
                        }
                    }
                    if (response.statusCode() != 200) {
                        throw new AuthException("Unexpected HTTP status code: "+ response.statusCode() + " while requesting a token at:" + tokenRequestURL);
                    }
                    final String body = response.body();

                    final JsonDataType tokenJson = JsonSimpleUtils.parse(body);
                    if (tokenJson instanceof JsonDataType.Object tokenJsonObject) {
                        // Token Endpoint Response: the response includes the access token and refresh token
                        final Optional<JsonDataType> tokenType = tokenJsonObject.value("token_type");
                        final Optional<JsonDataType> expiresIn = tokenJsonObject.value("expires_in");
                        final Optional<JsonDataType> accessToken = tokenJsonObject.value("access_token");
                        final Optional<JsonDataType> scope = tokenJsonObject.value("scope");
                        final Optional<JsonDataType> refreshToken = tokenJsonObject.value("refresh_token");
                       // TODO validate all

                        validateToken(accessToken.get().asJsonString().value());

                       if (accessToken.isPresent()
                               && accessToken.get() instanceof JsonDataType.String(String value)
                               && !value.isEmpty()) {
                           // Save current session deviceId as an authorized session
                           authorizedSessions.put(codeVerifier.deviceId, codeVerifier.deviceId);

                           return (_, lookup) -> {
                               lookup.put("user", scope);
                               final RelativeUrl redirectUrl = unauthorizedURLs.remove(httpRequest.deviceId().get());
                               return new AuthorizationState.Redirect(redirectUrl.toString());
                           };
                       }

                    } else {
                        throw new AuthException("Unexpected token format");
                    }

                }
            }

        } catch (AuthException e) {
            logger.log(System.Logger.Level.ERROR, "OAuth PKCE flow authentication error", e);
        }
        logger.log(System.Logger.Level.DEBUG, "OAuth PKCE flow: not authorised");
        return (_, lookup) -> {
            lookup.remove("user");
            return new AuthorizationState.NotAuthorized();
        };
    }

    private boolean validateToken(String token) throws AuthException {
        final String[] parts = token.split("\\.");
        final JsonDataType header = JsonSimpleUtils.parse(decodeBase64(parts[0]));
        final JsonDataType payload = JsonSimpleUtils.parse(decodeBase64(parts[1]));
        final String signature = decodeBase64(parts[2]);
        // Check the expire timestamp
        //final long timestamp = payload.asJsonObject().value("exp").get().asJsonNumber().asLong();
        //if (System.currentTimeMillis() / 10 > timestamp) throw new AuthException("Invalid timestamp");


        return false;
    }

    private static String decodeBase64(String string) {
        return new String(Base64.getUrlDecoder().decode(string));
    }

    private static String generateRandomString(int length) {
        final SecureRandom secureRandom = new SecureRandom();
        final byte[] codeVerifier = new byte[length];
        secureRandom.nextBytes(codeVerifier);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(codeVerifier);
    }

    private String generateCodeChallange(String codeVerifier) throws UnsupportedEncodingException, NoSuchAlgorithmException {
        final byte[] bytes = codeVerifier.getBytes("US-ASCII");
        final MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        messageDigest.update(bytes, 0, bytes.length);
        final byte[] digest = messageDigest.digest();
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }




    @Override
    public ComponentView<AuthorizationState> componentView() {
        return _ -> authorizationState -> {
            if (authorizationState instanceof AuthorizationState.NotAuthorized) {
                return openComponentDefinition;
            } else if (authorizationState instanceof AuthorizationState.Redirect(String redirectUrl)) {
                return html().redirect(redirectUrl);
            } else if (authorizationState instanceof AuthorizationState.Authorized) {
                return protectedComponentDefinition;
            }
            throw new RuntimeException();
        };
    }



   public sealed interface AuthorizationState {
        record NotAuthorized() implements AuthorizationState {
        };

        record Redirect(String redirectUrl) implements AuthorizationState {
        }

        record Authorized<S>() implements AuthorizationState {
        }

        record Logout() implements AuthorizationState {
        }
   }

    private record SessionAuthorization(String deviceId, String codeVerifier) {
        private SessionAuthorization {
            Objects.requireNonNull(deviceId);
            Objects.requireNonNull(codeVerifier);
        }
    }

}
