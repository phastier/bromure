import AuthenticationServices
import CryptoKit
import Foundation

/// Handles MCP OAuth discovery, dynamic client registration, and
/// authorization-code-with-PKCE flow for HTTP MCP servers. Runs entirely
/// on the host — the VM never sees real OAuth credentials.
@MainActor
public final class MCPOAuthBroker: NSObject, ASWebAuthenticationPresentationContextProviding {

    public enum BrokerError: Error, LocalizedError {
        case discoveryFailed(String)
        case registrationFailed(String)
        case authorizationCancelled
        case tokenExchangeFailed(String)
        case refreshFailed(String)

        public var errorDescription: String? {
            switch self {
            case .discoveryFailed(let msg):     return "OAuth discovery failed: \(msg)"
            case .registrationFailed(let msg):  return "Client registration failed: \(msg)"
            case .authorizationCancelled:       return "Authorization was cancelled"
            case .tokenExchangeFailed(let msg): return "Token exchange failed: \(msg)"
            case .refreshFailed(let msg):       return "Token refresh failed: \(msg)"
            }
        }
    }

    struct AuthMetadata {
        let authorizationEndpoint: URL
        let tokenEndpoint: URL
        let registrationEndpoint: URL?
    }

    struct ClientRegistration {
        let clientID: String
        let clientSecret: String?
    }

    public struct AuthResult {
        public let accessToken: String
        public let refreshToken: String?
        public let expiresIn: Int?
        public let clientID: String
        public let clientSecret: String?
        public let authorizationEndpoint: String
        public let tokenEndpoint: String
        public let registrationEndpoint: String?
    }

    private static let callbackScheme = "bromure-ac-oauth"
    private static let redirectURI = "bromure-ac-oauth://callback"

    // MARK: - Public API

    public func authorizeServer(url: String) async throws -> AuthResult {
        guard let serverURL = URL(string: url) else {
            throw BrokerError.discoveryFailed("Invalid URL")
        }
        let metadata = try await discoverMetadata(serverURL: serverURL)
        let client = try await registerClient(metadata: metadata, serverURL: serverURL)
        let (code, verifier) = try await authorize(metadata: metadata, client: client)
        return try await exchangeCode(code, metadata: metadata, client: client, codeVerifier: verifier)
    }

    public static func refresh(state: MCPOAuthState) async throws -> MCPOAuthState {
        guard let refreshToken = state.refreshToken,
              let tokenURL = URL(string: state.tokenEndpoint) else {
            throw BrokerError.refreshFailed("No refresh token or invalid token endpoint")
        }
        var body = [
            "grant_type=refresh_token",
            "refresh_token=\(formEncode(refreshToken))",
            "client_id=\(formEncode(state.clientID))",
        ]
        if let secret = state.clientSecret {
            body.append("client_secret=\(formEncode(secret))")
        }
        var request = URLRequest(url: tokenURL)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.httpBody = Data(body.joined(separator: "&").utf8)
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            throw BrokerError.refreshFailed("HTTP \((response as? HTTPURLResponse)?.statusCode ?? 0)")
        }
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let accessToken = json["access_token"] as? String else {
            throw BrokerError.refreshFailed("Missing access_token in response")
        }
        var updated = state
        updated.accessToken = accessToken
        if let rt = json["refresh_token"] as? String {
            updated.refreshToken = rt
        }
        if let exp = json["expires_in"] as? Int {
            updated.expiresAt = Date().addingTimeInterval(TimeInterval(exp))
        }
        return updated
    }

    // MARK: - Discovery (RFC 8414)

    private func discoverMetadata(serverURL: URL) async throws -> AuthMetadata {
        guard var components = URLComponents(url: serverURL, resolvingAgainstBaseURL: false) else {
            throw BrokerError.discoveryFailed("Cannot parse URL")
        }
        components.path = "/.well-known/oauth-authorization-server"
        components.query = nil
        components.fragment = nil
        guard let discoveryURL = components.url else {
            throw BrokerError.discoveryFailed("Cannot construct discovery URL")
        }
        let (data, response) = try await URLSession.shared.data(from: discoveryURL)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            throw BrokerError.discoveryFailed(
                "Server returned \((response as? HTTPURLResponse)?.statusCode ?? 0)")
        }
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let authEP = json["authorization_endpoint"] as? String,
              let authURL = URL(string: authEP),
              let tokenEP = json["token_endpoint"] as? String,
              let tokenURL = URL(string: tokenEP) else {
            throw BrokerError.discoveryFailed("Missing required endpoints in metadata")
        }
        let regEP = (json["registration_endpoint"] as? String).flatMap(URL.init(string:))
        return AuthMetadata(
            authorizationEndpoint: authURL,
            tokenEndpoint: tokenURL,
            registrationEndpoint: regEP
        )
    }

    // MARK: - Dynamic Client Registration (RFC 7591)

    private func registerClient(metadata: AuthMetadata, serverURL: URL) async throws -> ClientRegistration {
        guard let regURL = metadata.registrationEndpoint else {
            throw BrokerError.registrationFailed(
                "Server does not support dynamic client registration")
        }
        let payload: [String: Any] = [
            "client_name": "Bromure AC",
            "redirect_uris": [Self.redirectURI],
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
        ]
        var request = URLRequest(url: regURL)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONSerialization.data(withJSONObject: payload)
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse, (200...201).contains(http.statusCode) else {
            throw BrokerError.registrationFailed(
                "HTTP \((response as? HTTPURLResponse)?.statusCode ?? 0)")
        }
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let clientID = json["client_id"] as? String else {
            throw BrokerError.registrationFailed("Missing client_id in response")
        }
        return ClientRegistration(
            clientID: clientID,
            clientSecret: json["client_secret"] as? String
        )
    }

    // MARK: - Authorization (PKCE + ASWebAuthenticationSession)

    private func authorize(
        metadata: AuthMetadata,
        client: ClientRegistration
    ) async throws -> (code: String, verifier: String) {
        let verifier = Self.generateCodeVerifier()
        let challenge = Self.codeChallenge(for: verifier)
        let state = UUID().uuidString

        var components = URLComponents(url: metadata.authorizationEndpoint,
                                       resolvingAgainstBaseURL: false)!
        components.queryItems = [
            URLQueryItem(name: "response_type", value: "code"),
            URLQueryItem(name: "client_id", value: client.clientID),
            URLQueryItem(name: "redirect_uri", value: Self.redirectURI),
            URLQueryItem(name: "code_challenge", value: challenge),
            URLQueryItem(name: "code_challenge_method", value: "S256"),
            URLQueryItem(name: "state", value: state),
        ]
        guard let authURL = components.url else {
            throw BrokerError.discoveryFailed("Cannot construct authorization URL")
        }
        let callbackURL: URL = try await withCheckedThrowingContinuation { continuation in
            let session = ASWebAuthenticationSession(
                url: authURL,
                callbackURLScheme: Self.callbackScheme
            ) { url, error in
                if let error = error as? ASWebAuthenticationSessionError,
                   error.code == .canceledLogin {
                    continuation.resume(throwing: BrokerError.authorizationCancelled)
                } else if let error {
                    continuation.resume(throwing: error)
                } else if let url {
                    continuation.resume(returning: url)
                } else {
                    continuation.resume(throwing: BrokerError.authorizationCancelled)
                }
            }
            session.presentationContextProvider = self
            session.prefersEphemeralWebBrowserSession = true
            session.start()
        }
        guard let cbComponents = URLComponents(url: callbackURL, resolvingAgainstBaseURL: false),
              let code = cbComponents.queryItems?.first(where: { $0.name == "code" })?.value,
              let returnedState = cbComponents.queryItems?.first(where: { $0.name == "state" })?.value,
              returnedState == state else {
            throw BrokerError.tokenExchangeFailed("Invalid callback — missing code or state mismatch")
        }
        return (code, verifier)
    }

    // MARK: - Token Exchange

    private func exchangeCode(
        _ code: String,
        metadata: AuthMetadata,
        client: ClientRegistration,
        codeVerifier: String
    ) async throws -> AuthResult {
        var body = [
            "grant_type=authorization_code",
            "code=\(Self.formEncode(code))",
            "redirect_uri=\(Self.formEncode(Self.redirectURI))",
            "client_id=\(Self.formEncode(client.clientID))",
            "code_verifier=\(Self.formEncode(codeVerifier))",
        ]
        if let secret = client.clientSecret {
            body.append("client_secret=\(Self.formEncode(secret))")
        }
        var request = URLRequest(url: metadata.tokenEndpoint)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.httpBody = Data(body.joined(separator: "&").utf8)
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            throw BrokerError.tokenExchangeFailed(
                "HTTP \((response as? HTTPURLResponse)?.statusCode ?? 0)")
        }
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let accessToken = json["access_token"] as? String else {
            throw BrokerError.tokenExchangeFailed("Missing access_token in response")
        }
        return AuthResult(
            accessToken: accessToken,
            refreshToken: json["refresh_token"] as? String,
            expiresIn: json["expires_in"] as? Int,
            clientID: client.clientID,
            clientSecret: client.clientSecret,
            authorizationEndpoint: metadata.authorizationEndpoint.absoluteString,
            tokenEndpoint: metadata.tokenEndpoint.absoluteString,
            registrationEndpoint: metadata.registrationEndpoint?.absoluteString
        )
    }

    // MARK: - ASWebAuthenticationPresentationContextProviding

    public func presentationAnchor(
        for session: ASWebAuthenticationSession
    ) -> ASPresentationAnchor {
        NSApp.keyWindow ?? NSApp.windows.first { $0.isVisible } ?? NSApp.windows[0]
    }

    // MARK: - PKCE Helpers

    private static func generateCodeVerifier() -> String {
        var bytes = [UInt8](repeating: 0, count: 32)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        return Data(bytes).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    private static func codeChallenge(for verifier: String) -> String {
        let digest = SHA256.hash(data: Data(verifier.utf8))
        return Data(digest).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    private static func formEncode(_ value: String) -> String {
        value.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)?
            .replacingOccurrences(of: "+", with: "%2B") ?? value
    }
}
