#
# This source file is part of the EdgeDB open source project.
#
# Copyright 2016-present MagicStack Inc. and the EdgeDB authors.
#
# Licensed under the Apache License, Version 2.0 (the "License")
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#


import contextvars
import uuid
import json
import base64
import datetime
import argon2
import os
import pickle
import re
import hashlib

from typing import Optional, cast
from email.message import EmailMessage

from edb.testbase import http as tb
from edb.server.protocol.auth_ext import jwt as auth_jwt
from edb.server.auth import JWKSet

ph = argon2.PasswordHasher()

HTTP_TEST_PORT: contextvars.ContextVar[str] = contextvars.ContextVar(
    'HTTP_TEST_PORT'
)

GOOGLE_DISCOVERY_DOCUMENT = {
    "issuer": "https://accounts.google.com",
    "authorization_endpoint": ("https://accounts.google.com/o/oauth2/v2/auth"),
    "device_authorization_endpoint": (
        "https://oauth2.googleapis.com/device/code"
    ),
    "token_endpoint": ("https://oauth2.googleapis.com/token"),
    "userinfo_endpoint": ("https://openidconnect.googleapis.com/v1/userinfo"),
    "revocation_endpoint": ("https://oauth2.googleapis.com/revoke"),
    "jwks_uri": ("https://www.googleapis.com/oauth2/v3/certs"),
    "response_types_supported": [
        "code",
        "token",
        "id_token",
        "code token",
        "code id_token",
        "token id_token",
        "code token id_token",
        "none",
    ],
    "subject_types_supported": ["public"],
    "id_token_signing_alg_values_supported": ["RS256"],
    "scopes_supported": ["openid", "email", "profile"],
    "token_endpoint_auth_methods_supported": [
        "client_secret_post",
        "client_secret_basic",
    ],
    "claims_supported": [
        "aud",
        "email",
        "email_verified",
        "exp",
        "family_name",
        "given_name",
        "iat",
        "iss",
        "locale",
        "name",
        "picture",
        "sub",
    ],
    "code_challenge_methods_supported": ["plain", "S256"],
}

AZURE_DISCOVERY_DOCUMENT = {
    "token_endpoint": (
        "https://login.microsoftonline.com/common/oauth2/v2.0/token"
    ),
    "token_endpoint_auth_methods_supported": [
        "client_secret_post",
        "private_key_jwt",
        "client_secret_basic",
    ],
    "jwks_uri": "https://login.microsoftonline.com/common/discovery/v2.0/keys",
    "response_modes_supported": ["query", "fragment", "form_post"],
    "subject_types_supported": ["pairwise"],
    "id_token_signing_alg_values_supported": ["RS256"],
    "response_types_supported": [
        "code",
        "id_token",
        "code id_token",
        "id_token token",
    ],
    "scopes_supported": ["openid", "profile", "email", "offline_access"],
    "issuer": "https://login.microsoftonline.com/{tenantid}/v2.0",
    "request_uri_parameter_supported": False,
    "userinfo_endpoint": "https://graph.microsoft.com/oidc/userinfo",
    "authorization_endpoint": (
        "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
    ),
    "device_authorization_endpoint": (
        "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode"
    ),
    "http_logout_supported": True,
    "frontchannel_logout_supported": True,
    "end_session_endpoint": (
        "https://login.microsoftonline.com/common/oauth2/v2.0/logout"
    ),
    "claims_supported": [
        "sub",
        "iss",
        "cloud_instance_name",
        "cloud_instance_host_name",
        "cloud_graph_host_name",
        "msgraph_host",
        "aud",
        "exp",
        "iat",
        "auth_time",
        "acr",
        "nonce",
        "preferred_username",
        "name",
        "tid",
        "ver",
        "at_hash",
        "c_hash",
        "email",
    ],
    "kerberos_endpoint": "https://login.microsoftonline.com/common/kerberos",
    "tenant_region_scope": None,
    "cloud_instance_name": "microsoftonline.com",
    "cloud_graph_host_name": "graph.windows.net",
    "msgraph_host": "graph.microsoft.com",
    "rbac_url": "https://pas.windows.net",
}

APPLE_DISCOVERY_DOCUMENT = {
    "issuer": "https://appleid.apple.com",
    "authorization_endpoint": "https://appleid.apple.com/auth/authorize",
    "token_endpoint": "https://appleid.apple.com/auth/token",
    "revocation_endpoint": "https://appleid.apple.com/auth/revoke",
    "jwks_uri": "https://appleid.apple.com/auth/keys",
    "response_types_supported": ["code"],
    "response_modes_supported": ["query", "fragment", "form_post"],
    "subject_types_supported": ["pairwise"],
    "id_token_signing_alg_values_supported": ["RS256"],
    "scopes_supported": ["openid", "email", "name"],
    "token_endpoint_auth_methods_supported": ["client_secret_post"],
    "claims_supported": [
        "aud",
        "email",
        "email_verified",
        "exp",
        "iat",
        "is_private_email",
        "iss",
        "nonce",
        "nonce_supported",
        "real_user_status",
        "sub",
        "transfer_sub",
    ],
}

SLACK_DISCOVERY_DOCUMENT = {
    "issuer": "https://slack.com",
    "authorization_endpoint": "https://slack.com/openid/connect/authorize",
    "token_endpoint": "https://slack.com/api/openid.connect.token",
    "userinfo_endpoint": "https://slack.com/api/openid.connect.userInfo",
    "jwks_uri": "https://slack.com/openid/connect/keys",
    "scopes_supported": ["openid", "profile", "email"],
    "response_types_supported": ["code"],
    "response_modes_supported": ["query"],
    "grant_types_supported": ["authorization_code"],
    "subject_types_supported": ["public"],
    "id_token_signing_alg_values_supported": ["RS256"],
    "claims_supported": ["sub", "auth_time", "iss"],
    "claims_parameter_supported": False,
    "request_parameter_supported": False,
    "request_uri_parameter_supported": True,
    "token_endpoint_auth_methods_supported": [
        "client_secret_post",
        "client_secret_basic",
    ],
}

GENERIC_OIDC_DISCOVERY_DOCUMENT = {
    "issuer": "https://example.com",
    "authorization_endpoint": "https://example.com/auth",
    "token_endpoint": "https://example.com/token",
    "userinfo_endpoint": "https://example.com/userinfo",
    "jwks_uri": "https://example.com/jwks",
    "scopes_supported": ["openid", "profile", "email"],
    "response_types_supported": ["code"],
    "response_modes_supported": ["query"],
    "grant_types_supported": ["authorization_code"],
    "subject_types_supported": ["public"],
    "id_token_signing_alg_values_supported": ["RS256"],
    "claims_supported": ["sub", "auth_time", "iss"],
    "claims_parameter_supported": False,
    "request_parameter_supported": False,
    "request_uri_parameter_supported": True,
    "token_endpoint_auth_methods_supported": [
        "client_secret_post",
        "client_secret_basic",
    ],
}


def utcnow():
    return datetime.datetime.now(datetime.timezone.utc)


def b64_decode_padding(s):
    N = 4
    extra = (N - (len(s) % N)) % N
    return base64.b64decode(s + '=' * extra)


SIGNING_KEY = 'a' * 32
GITHUB_SECRET = 'b' * 32
GOOGLE_SECRET = 'c' * 32
AZURE_SECRET = 'c' * 32
APPLE_SECRET = 'c' * 32
DISCORD_SECRET = 'd' * 32
SLACK_SECRET = 'd' * 32
GENERIC_OIDC_SECRET = 'e' * 32
APP_NAME = "Test App" * 13
LOGO_URL = "http://example.com/logo.png"
DARK_LOGO_URL = "http://example.com/darklogo.png"
BRAND_COLOR = "f0f8ff"
SENDER = f"sender@example.com"


class BaseAuthTestCase(tb.ExtAuthTestCase):
    TRANSACTION_ISOLATION = False
    PARALLELISM_GRANULARITY = 'suite'

    SETUP = [
        f"""
        CONFIGURE CURRENT DATABASE INSERT cfg::SMTPProviderConfig {{
            name := "email_hosting_is_easy",
            sender := "{SENDER}",
        }};

        CONFIGURE CURRENT DATABASE SET
        current_email_provider_name := "email_hosting_is_easy";

        CONFIGURE CURRENT DATABASE SET
        ext::auth::AuthConfig::auth_signing_key := '{SIGNING_KEY}';

        CONFIGURE CURRENT DATABASE SET
        ext::auth::AuthConfig::token_time_to_live := <duration>'24 hours';

        CONFIGURE CURRENT DATABASE SET
        ext::auth::AuthConfig::app_name := '{APP_NAME}';

        CONFIGURE CURRENT DATABASE SET
        ext::auth::AuthConfig::logo_url := '{LOGO_URL}';

        CONFIGURE CURRENT DATABASE SET
        ext::auth::AuthConfig::dark_logo_url := '{DARK_LOGO_URL}';

        CONFIGURE CURRENT DATABASE SET
        ext::auth::AuthConfig::brand_color := '{BRAND_COLOR}';

        CONFIGURE CURRENT DATABASE
        INSERT ext::auth::UIConfig {{
          redirect_to := 'https://example.com/app',
          redirect_to_on_signup := 'https://example.com/signup/app',
        }};

        CONFIGURE CURRENT DATABASE SET
        ext::auth::AuthConfig::allowed_redirect_urls := {{
            'https://example.com/app'
        }};

        CONFIGURE CURRENT DATABASE
        INSERT ext::auth::GitHubOAuthProvider {{
            secret := '{GITHUB_SECRET}',
            client_id := '{uuid.uuid4()}',
        }};

        CONFIGURE CURRENT DATABASE
        INSERT ext::auth::GoogleOAuthProvider {{
            secret := '{GOOGLE_SECRET}',
            client_id := '{uuid.uuid4()}',
        }};

        CONFIGURE CURRENT DATABASE
        INSERT ext::auth::AzureOAuthProvider {{
            secret := '{AZURE_SECRET}',
            client_id := '{uuid.uuid4()}',
            additional_scope := 'offline_access',
        }};

        CONFIGURE CURRENT DATABASE
        INSERT ext::auth::AppleOAuthProvider {{
            secret := '{APPLE_SECRET}',
            client_id := '{uuid.uuid4()}',
        }};

        CONFIGURE CURRENT DATABASE
        INSERT ext::auth::DiscordOAuthProvider {{
            secret := '{DISCORD_SECRET}',
            client_id := '{uuid.uuid4()}',
        }};

        CONFIGURE CURRENT DATABASE
        INSERT ext::auth::SlackOAuthProvider {{
            secret := '{SLACK_SECRET}',
            client_id := '{uuid.uuid4()}',
        }};

        CONFIGURE CURRENT DATABASE
        INSERT ext::auth::OpenIDConnectProvider {{
            secret := '{GENERIC_OIDC_SECRET}',
            client_id := '{uuid.uuid4()}',
            name := 'generic_oidc',
            display_name := 'My Generic OIDC Provider',
            issuer_url := 'https://example.com',
            additional_scope := 'custom_provider_scope_string',
        }};

        CONFIGURE CURRENT DATABASE
        INSERT ext::auth::EmailPasswordProviderConfig {{
            require_verification := false,
        }};

        CONFIGURE CURRENT DATABASE
        INSERT ext::auth::WebAuthnProviderConfig {{
            relying_party_origin := 'https://example.com:8080',
            require_verification := false,
        }};

        CONFIGURE CURRENT DATABASE
        INSERT ext::auth::MagicLinkProviderConfig {{}};

        # Pure testing code:
        CREATE TYPE TestUser;
        ALTER TYPE TestUser {{
            CREATE REQUIRED LINK identity: ext::auth::Identity {{
                SET default := (GLOBAL ext::auth::ClientTokenIdentity)
            }};
        }};

        """,
    ]

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.loop.run_until_complete(
            cls._wait_for_db_config('ext::auth::AuthConfig::providers')
        )

    mock_oauth_server: tb.MockHttpServer
    mock_net_server: tb.MockHttpServer
    jwkset_cache: dict[str, JWKSet] = {}

    def setUp(self):
        self.mock_oauth_server = tb.MockHttpServer(
            handler_type=tb.MultiHostMockHttpServerHandler
        )
        self.mock_oauth_server.start()
        HTTP_TEST_PORT.set(self.mock_oauth_server.get_base_url())

        self.mock_net_server = tb.MockHttpServer()
        self.mock_net_server.start()
        super().setUp()

    def tearDown(self):
        if self.mock_oauth_server is not None:
            self.mock_oauth_server.stop()
        if self.mock_net_server is not None:
            self.mock_net_server.stop()
        self.mock_oauth_server = None
        super().tearDown()

    def signing_key(self):
        return auth_jwt.SigningKey(
            lambda: SIGNING_KEY,
            self.http_addr,
            is_key_for_testing=True,
        )

    @classmethod
    def get_setup_script(cls):
        res = super().get_setup_script()

        import os.path

        # Reload the extension package from the file if RELOAD is true.
        RELOAD = False

        if RELOAD:
            root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            with open(os.path.join(root, 'edb/lib/ext/auth.edgeql')) as f:
                contents = f.read()
            to_add = (
                '''
                drop extension package auth version '1.0';
                create extension auth;
            '''
                + contents
            )
            splice = '__internal_testmode := true;'
            res = res.replace(splice, splice + to_add)

        return res

    @classmethod
    def http_con_send_request(self, *args, headers=None, **kwargs):
        """Inject a test header.

        It's recognized by the server when explicitly run in the test mode.

        http_con_request() calls this method.
        """
        test_port = HTTP_TEST_PORT.get(None)
        if test_port is not None:
            if headers is None:
                headers = {}
            headers['x-edgedb-oauth-test-server'] = test_port
        return super().http_con_send_request(*args, headers=headers, **kwargs)

    async def get_provider_config_by_name(self, fqn: str):
        return await self.con.query_required_single(
            """
            SELECT assert_exists(
                cfg::Config.extensions[is ext::auth::AuthConfig].providers {
                    *,
                    verification_method := (
                      [is ext::auth::EmailPasswordProviderConfig].verification_method
                      ?? [is ext::auth::MagicLinkProviderConfig].verification_method
                      ?? [is ext::auth::WebAuthnProviderConfig].verification_method
                    ),
                    [is ext::auth::OAuthProviderConfig].client_id,
                    [is ext::auth::OAuthProviderConfig].additional_scope,
                } filter .name = <str>$0
            )
            """,  # noqa: E501
            fqn,
        )

    async def get_builtin_provider_config_by_name(self, provider_name: str):
        return await self.get_provider_config_by_name(
            f"builtin::{provider_name}"
        )

    async def get_auth_config_value(self, key: str):
        return await self.con.query_single(
            f"""
            SELECT assert_single(
                cfg::Config.extensions[is ext::auth::AuthConfig]
                    .{key}
            )
            """
        )

    def maybe_get_cookie_value(
        self, headers: dict[str, str], name: str
    ) -> Optional[str]:
        set_cookie = headers.get("set-cookie")
        if set_cookie is not None:
            (k, v) = set_cookie.split(";", 1)[0].split("=", 1)
            if k == name:
                return v

        return None

    def maybe_get_auth_token(self, headers: dict[str, str]) -> Optional[str]:
        return self.maybe_get_cookie_value(headers, "edgedb-session")

    def _verify_email_file(self, email):
        file_name_hash = hashlib.sha256(f"{SENDER}{email}".encode()).hexdigest()
        test_file = os.environ.get(
            "EDGEDB_TEST_EMAIL_FILE",
            f"/tmp/edb-test-email-{file_name_hash}.pickle",
        )
        if not os.path.exists(test_file):
            return None, None

        with open(test_file, "rb") as f:
            email_args = pickle.load(f)

        self.assertEqual(email_args["sender"], SENDER)
        self.assertEqual(email_args["recipients"], email)

        msg = cast(EmailMessage, email_args["message"]).get_body(("html",))
        assert msg is not None
        html_email = msg.get_payload(decode=True).decode("utf-8")

        # Try to find link
        match_link = re.search(
            r'<p style="word-break: break-all">([^<]+)', html_email
        )
        link = match_link.group(1) if match_link else None

        # Try to find code
        match_code = re.search(r'(?:^|\s)(\d{6})(?:\s|$)', html_email)
        code = match_code.group(1) if match_code else None

        return link, code

    def generate_and_serve_jwk(
        self,
        client_id: str,
        jwk_cert_url: str,
        token_url: str,
        issuer: str,
        access_token_name: str,
        sub: str = "1",
    ) -> tuple[str, str, str]:
        parts = jwk_cert_url.split("/", 3)
        host = parts[0] + "//" + parts[2]
        path = parts[3]
        jwks_request = (
            "GET",
            host,
            path,
        )

        # Because we have an internal cache, ensure that we only generate one
        # set per issuer
        jwks = self.jwkset_cache.get(issuer)
        if jwks is None:
            jwks = JWKSet()
            jwks.default_signing_context.set_issuer(issuer)
            jwks.generate(kid=None, kty="RS256")
            self.jwkset_cache[issuer] = jwks

        jwk_json = jwks.export_json(private_keys=False).decode()

        self.mock_oauth_server.register_route_handler(*jwks_request)(
            (
                jwk_json,
                200,
            )
        )

        parts = token_url.split("/", 3)
        host = parts[0] + "//" + parts[2]
        path = parts[3]
        token_request = (
            "POST",
            host,
            path,
        )

        jwks.default_signing_context.set_issuer(issuer)
        jwks.default_signing_context.set_audience(client_id)
        jwks.default_signing_context.set_expiry(3600)
        jwks.default_signing_context.set_not_before(30)

        id_token = jwks.sign(
            {
                "sub": sub,
                "email": "test@example.com",
            }
        )

        self.mock_oauth_server.register_route_handler(*token_request)(
            (
                json.dumps(
                    {
                        "access_token": access_token_name,
                        "id_token": id_token,
                        "scope": "openid",
                        "token_type": "bearer",
                    }
                ),
                200,
            )
        )
        return token_request
