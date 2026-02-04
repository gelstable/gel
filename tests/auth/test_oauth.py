import base64
import contextlib
import hashlib
import json
import os
import urllib.parse
from dataclasses import dataclass
from typing import Any, Mapping, Optional

from edb.server.protocol.auth_ext import jwt as auth_jwt
from .base import BaseAuthTestCase
from .base import (
    GITHUB_SECRET,
    GOOGLE_SECRET,
    AZURE_SECRET,
    APPLE_SECRET,
    DISCORD_SECRET,
    SLACK_SECRET,
    GENERIC_OIDC_SECRET,
    GOOGLE_DISCOVERY_DOCUMENT,
    AZURE_DISCOVERY_DOCUMENT,
    APPLE_DISCOVERY_DOCUMENT,
    SLACK_DISCOVERY_DOCUMENT,
    GENERIC_OIDC_DISCOVERY_DOCUMENT,
    utcnow,
)


@dataclass(frozen=True)
class OAuthCallbackConfig:
    provider_name: str
    client_secret: Optional[str]
    token_request_url: Optional[str]
    token_response_body: Optional[Mapping[str, Any]] = None
    user_info_request_url: Optional[str] = None
    user_info_response_body: Optional[Mapping[str, Any]] = None
    issuer_url: Optional[str] = None
    expected_identity_issuer: Optional[str] = None
    webhook_verification: bool = True
    callback_method: str = "GET"
    discovery_url: Optional[str] = None
    discovery_document: Optional[Mapping[str, Any]] = None
    jwks_url: Optional[str] = None
    jwks_issuer: Optional[str] = None
    jwks_token_url: Optional[str] = None
    jwks_access_token_name: str = "access_token"
    is_builtin: bool = True
    verify_identity: bool = True


class TestOAuth(BaseAuthTestCase):
    async def _test_oauth_authorize(
        self,
        provider_name,
        expected_scope,
        expected_path,
        expected_scheme="https",
        expected_hostname=None,
        discovery_url=None,
        discovery_document=None,
        is_builtin=True,
    ):
        with self.http_con() as http_con:
            if is_builtin:
                provider_config = (
                    await self.get_builtin_provider_config_by_name(
                        provider_name
                    )
                )
            else:
                provider_config = await self.get_provider_config_by_name(
                    provider_name
                )

            p_name = provider_config.name
            client_id = provider_config.client_id
            redirect_to = f"{self.http_addr}/some/path"
            callback_url = f"{self.http_addr}/some/callback/url"

            if discovery_url and discovery_document:
                parts = discovery_url.split("/", 3)
                host = parts[0] + "//" + parts[2]
                path = parts[3] if len(parts) > 3 else ""
                discovery_request = (
                    "GET",
                    host,
                    path,
                )
                self.mock_oauth_server.register_route_handler(
                    *discovery_request
                )(
                    (
                        json.dumps(discovery_document),
                        200,
                    )
                )

            challenge = (
                base64.urlsafe_b64encode(
                    hashlib.sha256(
                        base64.urlsafe_b64encode(os.urandom(43)).rstrip(b'=')
                    ).digest()
                )
                .rstrip(b'=')
                .decode()
            )
            query = {
                "provider": p_name,
                "redirect_to": redirect_to,
                "challenge": challenge,
                "callback_url": callback_url,
            }

            _, headers, status = self.http_con_request(
                http_con,
                query,
                path="authorize",
            )

            self.assertEqual(status, 302)

            location = headers.get("location")
            assert location is not None
            url = urllib.parse.urlparse(location)
            qs = urllib.parse.parse_qs(url.query, keep_blank_values=True)
            self.assertEqual(url.scheme, expected_scheme)
            if expected_hostname:
                self.assertEqual(url.hostname, expected_hostname)
            self.assertEqual(url.path, expected_path)

            if expected_scope is not None:
                self.assertEqual(qs.get("scope"), [expected_scope])

            state = qs.get("state")
            assert state is not None

            claims = auth_jwt.OAuthStateToken.verify(
                state[0], self.signing_key()
            )
            self.assertEqual(claims.provider, p_name)
            self.assertEqual(claims.redirect_to, redirect_to)

            self.assertEqual(qs.get("redirect_uri"), [callback_url])
            self.assertEqual(qs.get("client_id"), [client_id])

            pkce = await self.con.query(
                """
                select ext::auth::PKCEChallenge
                filter .challenge = <str>$challenge
                """,
                challenge=challenge,
            )
            self.assertEqual(len(pkce), 1)

            # Replay attack check
            _, _, repeat_status = self.http_con_request(
                http_con,
                query,
                path="authorize",
            )
            self.assertEqual(repeat_status, 302)

            repeat_pkce = await self.con.query_single(
                """
                select ext::auth::PKCEChallenge
                filter .challenge = <str>$challenge
                """,
                challenge=challenge,
            )
            self.assertEqual(pkce[0].id, repeat_pkce.id)

    async def _test_oauth_callback(self, config: OAuthCallbackConfig):
        provider_name = config.provider_name
        client_secret = config.client_secret
        token_request_url = config.token_request_url
        token_response_body = config.token_response_body
        user_info_request_url = config.user_info_request_url
        user_info_response_body = config.user_info_response_body
        issuer_url = config.issuer_url
        expected_identity_issuer = config.expected_identity_issuer
        webhook_verification = config.webhook_verification
        callback_method = config.callback_method
        discovery_url = config.discovery_url
        discovery_document = config.discovery_document
        jwks_url = config.jwks_url
        jwks_issuer = config.jwks_issuer
        jwks_token_url = config.jwks_token_url
        jwks_access_token_name = config.jwks_access_token_name
        is_builtin = config.is_builtin
        verify_identity = config.verify_identity

        if expected_identity_issuer is None:
            expected_identity_issuer = issuer_url

        base_url = self.mock_net_server.get_base_url().rstrip("/")
        webhook_url = f"{base_url}/webhook-01"

        async with contextlib.AsyncExitStack() as stack:
            webhook_request = None
            if webhook_verification:
                await stack.enter_async_context(
                    self.temporary_config(
                        (
                            """
                            CONFIGURE CURRENT DATABASE
                            INSERT ext::auth::WebhookConfig {
                                url := <str>$url,
                                events := {
                                    ext::auth::WebhookEvent.IdentityCreated,
                                },
                            };
                            """,
                            {"url": webhook_url},
                        ),
                        (
                            """
                            CONFIGURE CURRENT DATABASE
                            RESET ext::auth::WebhookConfig
                            filter .url = <str>$url;
                            """,
                            {"url": webhook_url},
                        ),
                        "ext::auth::AuthConfig::webhooks",
                    )
                )
                webhook_request = (
                    "POST",
                    base_url,
                    "/webhook-01",
                )
                self.mock_net_server.register_route_handler(*webhook_request)(
                    (
                        "",
                        204,
                    )
                )

            if is_builtin:
                provider_config = (
                    await self.get_builtin_provider_config_by_name(
                        provider_name
                    )
                )
            else:
                provider_config = await self.get_provider_config_by_name(
                    provider_name
                )

            p_name = provider_config.name
            client_id = provider_config.client_id

            # Setup Discovery
            if discovery_url and discovery_document:
                parts = discovery_url.split("/", 3)
                host = parts[0] + "//" + parts[2]
                path = parts[3] if len(parts) > 3 else ""
                discovery_req_key = ("GET", host, path)
                self.mock_oauth_server.register_route_handler(
                    *discovery_req_key
                )(
                    (
                        json.dumps(discovery_document),
                        200,
                        {"cache-control": "max-age=3600"},
                    )
                )

            # Setup Token Response
            token_request = None
            if jwks_url:
                assert jwks_token_url is not None
                assert jwks_issuer is not None
                # Use helper for JWK based token response (ID Token)
                token_request = self.generate_and_serve_jwk(
                    client_id,
                    jwks_url,
                    jwks_token_url,
                    jwks_issuer,
                    jwks_access_token_name,
                )
            else:
                assert token_request_url is not None
                assert token_response_body is not None
                # Standard manual token response
                parts = token_request_url.split("/", 3)
                host = parts[0] + "//" + parts[2]
                path = parts[3] if len(parts) > 3 else ""
                token_request = ("POST", host, path)

                self.mock_oauth_server.register_route_handler(*token_request)(
                    (
                        json.dumps(token_response_body),
                        200,
                    )
                )

            assert token_request is not None

            # Setup User Info Response
            user_request = None
            if user_info_request_url and user_info_response_body:
                parts = user_info_request_url.split("/", 3)
                host = parts[0] + "//" + parts[2]
                path = parts[3] if len(parts) > 3 else ""
                user_request = ("GET", host, path)
                self.mock_oauth_server.register_route_handler(*user_request)(
                    (
                        json.dumps(user_info_response_body),
                        200,
                    )
                )

            with self.http_con() as http_con:
                challenge = (
                    base64.urlsafe_b64encode(
                        hashlib.sha256(
                            base64.urlsafe_b64encode(os.urandom(43)).rstrip(
                                b'='
                            )
                        ).digest()
                    )
                    .rstrip(b'=')
                    .decode()
                )
                await self.con.query(
                    """
                    insert ext::auth::PKCEChallenge {
                        challenge := <str>$challenge,
                    }
                    """,
                    challenge=challenge,
                )

                state_claims = auth_jwt.OAuthStateToken(
                    provider=p_name,
                    redirect_to=f"{self.http_addr}/some/path",
                    challenge=challenge,
                    redirect_uri=f"{self.http_addr}/auth/oauth/code",
                )
                state_token = state_claims.sign(self.signing_key())

                request_body: bytes = b""
                request_headers: Optional[dict[str, str]] = None
                request_method = "GET"
                request_params: Optional[dict[str, str]] = None

                if callback_method == "POST":
                    request_method = "POST"
                    request_body = urllib.parse.urlencode(
                        {"state": state_token, "code": "abc123"}
                    ).encode()
                    request_headers = {
                        "Content-Type": "application/x-www-form-urlencoded"
                    }
                else:
                    request_params = {"state": state_token, "code": "abc123"}

                data, headers, status = self.http_con_request(
                    http_con,
                    request_params,  # params (2nd arg)
                    path="callback",
                    method=request_method,
                    body=request_body,
                    headers=request_headers,
                )

                self.assertEqual(data, b"")
                self.assertEqual(status, 302)

                location = headers.get("location")
                assert location is not None
                server_url = urllib.parse.urlparse(self.http_addr)
                url = urllib.parse.urlparse(location)
                self.assertEqual(url.scheme, server_url.scheme)
                self.assertEqual(url.hostname, server_url.hostname)
                self.assertEqual(url.path, f"{server_url.path}/some/path")

                requests_for_token = self.mock_oauth_server.requests[
                    token_request
                ]
                self.assertEqual(len(requests_for_token), 1)
                body = requests_for_token[0].body
                assert body is not None

                # Check token request body
                if isinstance(body, bytes):
                    body_str = body.decode()
                else:
                    body_str = body

                try:
                    token_req_body = json.loads(body_str)
                except json.JSONDecodeError:
                    token_req_body = urllib.parse.parse_qs(body_str)

                # Handling the difference between JSON body and Form body
                # parsing
                def get_val(d, k):
                    v = d.get(k)
                    if isinstance(v, list):
                        return v[0]
                    return v

                self.assertEqual(
                    get_val(token_req_body, "grant_type"), "authorization_code"
                )
                self.assertEqual(get_val(token_req_body, "code"), "abc123")
                self.assertEqual(
                    get_val(token_req_body, "client_id"), client_id
                )
                if client_secret:
                    self.assertEqual(
                        get_val(token_req_body, "client_secret"), client_secret
                    )
                self.assertEqual(
                    get_val(token_req_body, "redirect_uri"),
                    f"{self.http_addr}/auth/oauth/code",
                )

                if verify_identity:
                    if user_request:
                        assert user_info_response_body is not None
                        requests_for_user = self.mock_oauth_server.requests[
                            user_request
                        ]
                        self.assertEqual(len(requests_for_user), 1)
                        # For OIDC, we expect the sub from ID token or userinfo.
                        subject = user_info_response_body.get(
                            "sub", user_info_response_body.get("id")
                        )
                    else:
                        # Apple / ID Token case
                        subject = "1"  # Default from generate_and_serve_jwk

                    identity = await self.con.query(
                        """
                        SELECT ext::auth::Identity
                        FILTER .subject = <str>$subject
                        AND .issuer = <str>$issuer
                        """,
                        subject=str(subject),
                        issuer=expected_identity_issuer,
                    )
                    self.assertEqual(len(identity), 1)

                    if webhook_verification:
                        assert webhook_request is not None
                        # Test Webhook side effect
                        async for tr in self.try_until_succeeds(
                            delay=2,
                            timeout=15,
                            ignore=AssertionError,
                        ):
                            async with tr:
                                requests_for_webhook = (
                                    self.mock_net_server.requests.get(
                                        webhook_request, []
                                    )
                                )
                                self.assertEqual(len(requests_for_webhook), 1)

                        body = requests_for_webhook[0].body
                        assert body is not None
                        event_data = json.loads(body)
                        self.assertEqual(
                            event_data["event_type"], "IdentityCreated"
                        )
                        self.assertEqual(
                            event_data["identity_id"], str(identity[0].id)
                        )

                    pkce_object = await self.con.query(
                        """
                        SELECT ext::auth::PKCEChallenge
                        { id, auth_token, refresh_token }
                        filter .identity.id = <uuid>$identity_id
                        """,
                        identity_id=identity[0].id,
                    )

                    self.assertEqual(len(pkce_object), 1)

                    # Auth token check
                    expected_token = None
                    if token_response_body:
                        expected_token = token_response_body.get("access_token")
                    elif jwks_access_token_name:
                        expected_token = jwks_access_token_name

                    self.assertEqual(pkce_object[0].auth_token, expected_token)

                    if user_info_response_body and user_request:
                        # Update mock to return same user
                        self.mock_oauth_server.register_route_handler(
                            *user_request
                        )(
                            (
                                json.dumps(user_info_response_body),
                                200,
                            )
                        )

                    self.http_con_request(
                        http_con,
                        request_params,
                        path="callback",
                        method=request_method,
                        body=request_body,
                        headers=request_headers,
                    )

                    same_identity = await self.con.query(
                        """
                        SELECT ext::auth::Identity
                        FILTER .subject = <str>$subject
                        AND .issuer = <str>$issuer
                        """,
                        subject=str(subject),
                        issuer=expected_identity_issuer,
                    )
                    self.assertEqual(len(same_identity), 1)
                    self.assertEqual(identity[0].id, same_identity[0].id)

    async def test_oauth_github_flow(self):
        await self._test_oauth_authorize(
            "oauth_github",
            expected_scope="read:user user:email ",
            expected_path="/login/oauth/authorize",
            expected_hostname="github.com",
        )

        await self._test_oauth_callback(
            OAuthCallbackConfig(
                provider_name="oauth_github",
                client_secret=GITHUB_SECRET,
                token_request_url=(
                    "https://github.com/login/oauth/access_token"
                ),
                token_response_body={
                    "access_token": "github_access_token",
                    "scope": "read:user",
                    "token_type": "bearer",
                },
                user_info_request_url="https://api.github.com/user",
                user_info_response_body={
                    "id": 1,
                    "login": "octocat",
                    "name": "monalisa octocat",
                    "email": "octocat@example.com",
                    "avatar_url": "https://example.com/example.jpg",
                    "updated_at": utcnow().isoformat(),
                },
                issuer_url="https://github.com",
            )
        )

    async def test_oauth_discord_flow(self):
        await self._test_oauth_authorize(
            "oauth_discord",
            expected_scope="email identify ",
            expected_path="/oauth2/authorize",
            expected_hostname="discord.com",
        )

        await self._test_oauth_callback(
            OAuthCallbackConfig(
                provider_name="oauth_discord",
                client_secret=DISCORD_SECRET,
                token_request_url="https://discord.com/api/oauth2/token",
                token_response_body={
                    "access_token": "discord_access_token",
                    "scope": "read:user",
                    "token_type": "bearer",
                },
                user_info_request_url=("https://discord.com/api/v10/users/@me"),
                user_info_response_body={
                    "id": 1,
                    "username": "dischord",
                    "global_name": "Ian MacKaye",
                    "email": "ian@example.com",
                    "picture": "https://example.com/example.jpg",
                },
                issuer_url="https://discord.com",
                webhook_verification=False,
            )
        )

    async def test_oauth_google_flow(self):
        await self._test_oauth_authorize(
            "oauth_google",
            expected_scope="openid profile email ",
            expected_path="/o/oauth2/v2/auth",
            expected_hostname="accounts.google.com",
            discovery_url="https://accounts.google.com/.well-known/openid-configuration",
            discovery_document=GOOGLE_DISCOVERY_DOCUMENT,
        )

        await self._test_oauth_callback(
            OAuthCallbackConfig(
                provider_name="oauth_google",
                client_secret=GOOGLE_SECRET,
                token_request_url="https://oauth2.googleapis.com/token",
                issuer_url="https://accounts.google.com",
                discovery_url=(
                    "https://accounts.google.com/"
                    ".well-known/openid-configuration"
                ),
                discovery_document=GOOGLE_DISCOVERY_DOCUMENT,
                jwks_url="https://www.googleapis.com/oauth2/v3/certs",
                jwks_token_url="https://oauth2.googleapis.com/token",
                jwks_issuer="https://accounts.google.com",
                jwks_access_token_name="google_access_token",
                webhook_verification=False,
            )
        )

    async def test_oauth_azure_flow(self):
        await self._test_oauth_authorize(
            "oauth_azure",
            expected_scope="openid profile email offline_access",
            expected_path="/common/oauth2/v2.0/authorize",
            expected_hostname="login.microsoftonline.com",
            discovery_url="https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration",
            discovery_document=AZURE_DISCOVERY_DOCUMENT,
        )

        await self._test_oauth_callback(
            OAuthCallbackConfig(
                provider_name="oauth_azure",
                client_secret=AZURE_SECRET,
                token_request_url=None,
                issuer_url=(
                    "https://login.microsoftonline.com/{tenantid}/v2.0"
                ),
                expected_identity_issuer=("https://login.microsoftonline.com"),
                discovery_url=(
                    "https://login.microsoftonline.com/common/v2.0/"
                    ".well-known/openid-configuration"
                ),
                discovery_document=AZURE_DISCOVERY_DOCUMENT,
                jwks_url=(
                    "https://login.microsoftonline.com/common/discovery/"
                    "v2.0/keys"
                ),
                jwks_token_url=(
                    "https://login.microsoftonline.com/common/oauth2/v2.0/token"
                ),
                jwks_issuer="https://login.microsoftonline.com",
                jwks_access_token_name="azure_access_token",
                webhook_verification=False,
                verify_identity=False,
            )
        )

    async def test_oauth_apple_flow(self):
        await self._test_oauth_authorize(
            "oauth_apple",
            expected_scope="openid email name ",
            expected_path="/auth/authorize",
            expected_hostname="appleid.apple.com",
            discovery_url="https://appleid.apple.com/.well-known/openid-configuration",
            discovery_document=APPLE_DISCOVERY_DOCUMENT,
        )

        await self._test_oauth_callback(
            OAuthCallbackConfig(
                provider_name="oauth_apple",
                client_secret=APPLE_SECRET,
                token_request_url=None,
                issuer_url="https://appleid.apple.com",
                discovery_url=(
                    "https://appleid.apple.com/.well-known/openid-configuration"
                ),
                discovery_document=APPLE_DISCOVERY_DOCUMENT,
                jwks_url="https://appleid.apple.com/auth/keys",
                jwks_token_url="https://appleid.apple.com/auth/token",
                jwks_issuer="https://appleid.apple.com",
                jwks_access_token_name="apple_access_token",
                callback_method="POST",
                webhook_verification=False,
            )
        )

    async def test_oauth_slack_flow(self):
        await self._test_oauth_authorize(
            "oauth_slack",
            expected_scope="openid profile email ",
            expected_path="/openid/connect/authorize",
            expected_hostname="slack.com",
            discovery_url="https://slack.com/.well-known/openid-configuration",
            discovery_document=SLACK_DISCOVERY_DOCUMENT,
        )

        await self._test_oauth_callback(
            OAuthCallbackConfig(
                provider_name="oauth_slack",
                client_secret=SLACK_SECRET,
                token_request_url=None,
                issuer_url="https://slack.com",
                discovery_url=(
                    "https://slack.com/.well-known/openid-configuration"
                ),
                discovery_document=SLACK_DISCOVERY_DOCUMENT,
                jwks_url="https://slack.com/openid/connect/keys",
                jwks_token_url=("https://slack.com/api/openid.connect.token"),
                jwks_issuer="https://slack.com",
                jwks_access_token_name="slack_access_token",
                webhook_verification=False,
            )
        )

    async def test_oauth_generic_oidc_flow(self):
        await self._test_oauth_authorize(
            "generic_oidc",
            expected_scope="openid profile email custom_provider_scope_string",
            expected_path="/auth",
            expected_hostname="example.com",
            discovery_url="https://example.com/.well-known/openid-configuration",
            discovery_document=GENERIC_OIDC_DISCOVERY_DOCUMENT,
            is_builtin=False,
        )

        await self._test_oauth_callback(
            OAuthCallbackConfig(
                provider_name="generic_oidc",
                client_secret=GENERIC_OIDC_SECRET,
                token_request_url=None,
                issuer_url="https://example.com",
                discovery_url=(
                    "https://example.com/.well-known/openid-configuration"
                ),
                discovery_document=GENERIC_OIDC_DISCOVERY_DOCUMENT,
                jwks_url="https://example.com/jwks",
                jwks_token_url="https://example.com/token",
                jwks_issuer="https://example.com",
                jwks_access_token_name="oidc_access_token",
                webhook_verification=False,
                is_builtin=False,
            )
        )

    async def test_oauth_callback_missing_provider(self):
        with self.http_con() as http_con:
            state_claims = auth_jwt.OAuthStateToken(
                provider=None,
                redirect_to=None,
                challenge=None,
                redirect_uri=None,
            )
            state_token = state_claims.sign(self.signing_key())

            _, _, status = self.http_con_request(
                http_con,
                {"state": state_token, "code": "abc123"},
                path="callback",
            )

            self.assertEqual(status, 400)

    async def test_oauth_callback_wrong_key(self):
        with self.http_con() as http_con:
            provider_config = await self.get_builtin_provider_config_by_name(
                "oauth_github"
            )
            provider_name = provider_config.name

            state_claims = auth_jwt.OAuthStateToken(
                provider=provider_name,
                redirect_to=f"{self.http_addr}/some/path",
                challenge="1234",
                redirect_uri=f"{self.http_addr}/auth/oauth/code",
            )
            state_token = state_claims.sign(
                auth_jwt.SigningKey(lambda: 'wrong key', self.http_addr),
            )

            _, _, status = self.http_con_request(
                http_con,
                {"state": state_token, "code": "abc123"},
                path="callback",
            )

            self.assertEqual(status, 400)

    async def test_oauth_unknown_provider(self):
        with self.http_con() as http_con:
            state_claims = auth_jwt.OAuthStateToken(
                provider="beepboopbeep",
                redirect_to="https://example.com",
                redirect_to_on_signup=None,
                challenge="challenge",
                redirect_uri=f"{self.http_addr}/auth/oauth/code",
            )
            state_token = state_claims.sign(self.signing_key())

            body, _, status = self.http_con_request(
                http_con,
                {"state": state_token, "code": "abc123"},
                path="callback",
            )

            try:
                body_json = json.loads(body)
                self.assertIsNotNone(body_json)
            except json.JSONDecodeError:
                self.fail("Failed to parse JSON from response body")

            self.assertEqual(status, 400)
            self.assertEqual(
                body_json.get("error"),
                {
                    "type": "InvalidData",
                    "message": "Invalid state token",
                },
            )

    async def test_oauth_callback_failure_responses(self):
        provider_config = await self.get_builtin_provider_config_by_name(
            "oauth_github"
        )
        provider_name = provider_config.name

        with self.http_con() as http_con:
            state_claims = auth_jwt.OAuthStateToken(
                provider=provider_name,
                redirect_to=f"{self.http_addr}/some/path",
                challenge="challenge",
                redirect_uri=f"{self.http_addr}/auth/oauth/code",
            )
            state_token = state_claims.sign(self.signing_key())

            # Test failure 01: error query param
            data, headers, status = self.http_con_request(
                http_con,
                {
                    "state": state_token,
                    "error": "access_denied",
                    "error_description": (
                        "The user has denied your application access"
                    ),
                },
                path="callback",
            )
            self.assertEqual(data.decode(), "")
            self.assertEqual(status, 302)

            location = headers.get("location")
            self.assertIsNotNone(location)
            server_url = urllib.parse.urlparse(self.http_addr)
            url = urllib.parse.urlparse(location)
            self.assertEqual(url.scheme, server_url.scheme)
            self.assertEqual(url.hostname, server_url.hostname)
            self.assertEqual(url.path, f"{server_url.path}/some/path")
            self.assertEqual(
                url.query,
                "error=access_denied"
                "&error_description="
                "The+user+has+denied+your+application+access",
            )

            # Test failure 02: missing code
            data, headers, status = self.http_con_request(
                http_con,
                {
                    "state": state_token,
                },
                path="callback",
            )

            try:
                body_json = json.loads(data)
            except json.JSONDecodeError:
                self.fail("Failed to parse JSON from response body")

            self.assertEqual(status, 400)
            self.assertEqual(
                body_json.get("error"),
                {
                    "type": "InvalidData",
                    "message": "Provider did not include the 'code' parameter "
                    "in callback",
                },
            )

    async def test_oauth_apple_redirect_on_signup(self):
        with self.http_con() as http_con:
            provider_config = await self.get_builtin_provider_config_by_name(
                "oauth_apple"
            )
            provider_name = provider_config.name
            client_id = provider_config.client_id

            discovery_request = (
                "GET",
                "https://appleid.apple.com",
                ".well-known/openid-configuration",
            )
            self.mock_oauth_server.register_route_handler(*discovery_request)(
                (
                    json.dumps(APPLE_DISCOVERY_DOCUMENT),
                    200,
                )
            )

            _token_request = self.generate_and_serve_jwk(
                client_id,
                "https://appleid.apple.com/auth/keys",
                "https://appleid.apple.com/auth/token",
                "https://appleid.apple.com",
                "apple_access_token",
                sub="2",
            )

            challenge = (
                base64.urlsafe_b64encode(
                    hashlib.sha256(
                        base64.urlsafe_b64encode(os.urandom(43)).rstrip(b'=')
                    ).digest()
                )
                .rstrip(b'=')
                .decode()
            )
            await self.con.query(
                """
                insert ext::auth::PKCEChallenge {
                    challenge := <str>$challenge,
                }
                """,
                challenge=challenge,
            )

            state_claims = auth_jwt.OAuthStateToken(
                provider=provider_name,
                redirect_to=f"{self.http_addr}/some/path",
                redirect_to_on_signup=f"{self.http_addr}/some/other/path",
                challenge=challenge,
                redirect_uri=f"{self.http_addr}/auth/oauth/code",
            )
            state_token = state_claims.sign(self.signing_key())

            request_body = urllib.parse.urlencode(
                {"state": state_token, "code": "abc123"}
            ).encode()

            data, headers, status = self.http_con_request(
                http_con,
                None,
                path="callback",
                method="POST",
                body=request_body,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )

            self.assertEqual(data, b"", data)
            self.assertEqual(status, 302)

            location = headers.get("location")
            assert location is not None
            server_url = urllib.parse.urlparse(self.http_addr)
            url = urllib.parse.urlparse(location)
            self.assertEqual(url.scheme, server_url.scheme)
            self.assertEqual(url.hostname, server_url.hostname)
            self.assertEqual(url.path, f"{server_url.path}/some/other/path")

            # Second request - login (should redirect to redirect_to)
            data, headers, status = self.http_con_request(
                http_con,
                None,
                path="callback",
                method="POST",
                body=request_body,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )

            self.assertEqual(data, b"")
            self.assertEqual(status, 302)

            location = headers.get("location")
            assert location is not None
            server_url = urllib.parse.urlparse(self.http_addr)
            url = urllib.parse.urlparse(location)
            self.assertEqual(url.scheme, server_url.scheme)
            self.assertEqual(url.hostname, server_url.hostname)
            self.assertEqual(url.path, f"{server_url.path}/some/path")
