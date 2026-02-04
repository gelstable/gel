import json
import uuid
import urllib.parse

from .base import BaseAuthTestCase


class TestMagicLink(BaseAuthTestCase):
    async def test_magic_link_flow(self):
        email = f"{uuid.uuid4()}@example.com"
        challenge = "test_challenge"
        callback_url = "https://example.com/app/auth/callback"
        redirect_on_failure = "https://example.com/app/auth/magic-link-failure"
        link_url = "https://example.com/app/magic-link/authenticate"

        with self.http_con() as http_con:
            # 1. Register with link_url
            body, _, status = self.http_con_request(
                http_con,
                method="POST",
                path="magic-link/register",
                body=json.dumps(
                    {
                        "provider": "builtin::local_magic_link",
                        "email": email,
                        "challenge": challenge,
                        "callback_url": callback_url,
                        "redirect_on_failure": redirect_on_failure,
                        "link_url": link_url,
                    }
                ).encode(),
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
            )
            self.assertEqual(status, 200, body)

            # Verify email and get token
            link, _ = self._verify_email_file(email)
            self.assertIsNotNone(link)
            magic_link_url = urllib.parse.urlparse(link)
            search_params = urllib.parse.parse_qs(magic_link_url.query)
            token = search_params.get("token", [None])[0]
            assert token is not None
            self.assertEqual(
                urllib.parse.urlunparse(
                    (
                        magic_link_url.scheme,
                        magic_link_url.netloc,
                        magic_link_url.path,
                        '',
                        '',
                        '',
                    )
                ),
                link_url,
            )

            # Authenticate
            _, headers, status = self.http_con_request(
                http_con,
                method="GET",
                path=f"magic-link/authenticate?token={token}",
            )

            self.assertEqual(status, 302)
            location = headers.get("location")
            assert location is not None
            self.assertTrue(location.startswith(callback_url))

            # 2. Sign in with existing user
            _, _, status = self.http_con_request(
                http_con,
                method="POST",
                path="magic-link/email",
                body=json.dumps(
                    {
                        "provider": "builtin::local_magic_link",
                        "email": email,
                        "challenge": challenge,
                        "callback_url": callback_url,
                        "redirect_on_failure": redirect_on_failure,
                        "link_url": link_url,
                    }
                ).encode(),
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
            )
            self.assertEqual(status, 200)

            # Verify email again
            link, _ = self._verify_email_file(email)
            self.assertIsNotNone(link)
            self.assertIn(link_url, link)

            # 3. Register WITHOUT link_url
            email_no_link = f"{uuid.uuid4()}@example.com"
            body, _, status = self.http_con_request(
                http_con,
                method="POST",
                path="magic-link/register",
                body=json.dumps(
                    {
                        "provider": "builtin::local_magic_link",
                        "email": email_no_link,
                        "challenge": challenge,
                        "callback_url": callback_url,
                        "redirect_on_failure": redirect_on_failure,
                    }
                ).encode(),
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
            )
            self.assertEqual(status, 200, body)

            link, _ = self._verify_email_file(email_no_link)
            self.assertIsNotNone(link)
            magic_link_url = urllib.parse.urlparse(link)
            self.assertEqual(
                urllib.parse.urlunparse(
                    (
                        magic_link_url.scheme,
                        magic_link_url.netloc,
                        magic_link_url.path,
                        '',
                        '',
                        '',
                    )
                ),
                f"{self.http_addr}/magic-link/authenticate",
            )

    async def test_magic_code_flow(self):
        await self.con.query(
            """
            CONFIGURE CURRENT DATABASE
            RESET ext::auth::MagicLinkProviderConfig;

            CONFIGURE CURRENT DATABASE
            INSERT ext::auth::MagicLinkProviderConfig {
                verification_method := ext::auth::VerificationMethod.Code,
            };
        """
        )

        try:
            email = f"{uuid.uuid4()}@example.com"

            with self.http_con() as http_con:
                # 1. Register with code
                body, _, status = self.http_con_request(
                    http_con,
                    method="POST",
                    path="magic-link/register",
                    body=json.dumps(
                        {
                            "provider": "builtin::local_magic_link",
                            "email": email,
                            # No challenge/redirect needed for code response
                        }
                    ).encode(),
                    headers={
                        "Content-Type": "application/json",
                        "Accept": "application/json",
                    },
                )
                self.assertEqual(status, 200, body)
                data = json.loads(body)
                self.assertEqual(data.get("code"), "true")
                self.assertEqual(data.get("signup"), "true")
                self.assertEqual(data.get("email"), email)

                expected_identity_id = await self.con.query_single(
                    """
                    with IDENTITY := (
                      select ext::auth::MagicLinkFactor
                      filter .email = <str>$email
                    ).identity
                    select IDENTITY.id;
                    """,
                    email=email,
                )
                self.assertEqual(
                    data.get("identity_id"), str(expected_identity_id)
                )

                # Verify email has code
                _, code = self._verify_email_file(email)
                self.assertIsNotNone(code)
                self.assertEqual(len(code), 6)

                # 2. Login with code (magic-link/email)
                body, _, status = self.http_con_request(
                    http_con,
                    method="POST",
                    path="magic-link/email",
                    body=json.dumps({"email": email}).encode(),
                    headers={
                        "Content-Type": "application/json",
                        "Accept": "application/json",
                    },
                )
                self.assertEqual(status, 200, body)
                data = json.loads(body)
                self.assertEqual(data.get("code"), "true")
                self.assertEqual(data.get("email"), email)

                _, code = self._verify_email_file(email)
                self.assertIsNotNone(code)

                # 3. Non-existent email should look the same (security)
                nonexistent_email = f"nonexistent-{uuid.uuid4()}@example.com"
                body, _, status = self.http_con_request(
                    http_con,
                    method="POST",
                    path="magic-link/email",
                    body=json.dumps({"email": nonexistent_email}).encode(),
                    headers={
                        "Content-Type": "application/json",
                        "Accept": "application/json",
                    },
                )
                self.assertEqual(status, 200, body)
                data = json.loads(body)
                self.assertEqual(data.get("code"), "true")
                self.assertEqual(data.get("email"), nonexistent_email)

                # Should NOT send email for non-existent user (unless
                # auto-signup is on, which is default false)
                link, code = self._verify_email_file(nonexistent_email)
                self.assertIsNone(link)
                self.assertIsNone(code)

        finally:
            await self.con.query(
                """
                CONFIGURE CURRENT DATABASE
                RESET ext::auth::MagicLinkProviderConfig;
                CONFIGURE CURRENT DATABASE
                INSERT ext::auth::MagicLinkProviderConfig {};
            """
            )

    async def test_magic_link_validation(self):
        email = f"{uuid.uuid4()}@example.com"
        callback_url = "https://example.com/app/auth/callback"
        redirect_on_failure = "https://example.com/app/auth/magic-link-failure"
        challenge = "test_challenge"
        link_url = "https://example.com/app/magic-link/authenticate"

        # Missing keys validation
        partial_keys = [
            {"challenge", "callback_url", "redirect_on_failure", "link_url"},
            {"challenge", "callback_url", "redirect_on_failure"},
            {"challenge", "callback_url", "link_url"},
            {"challenge", "redirect_on_failure", "link_url"},
            {"callback_url", "redirect_on_failure", "link_url"},
            {"challenge", "callback_url"},
            {"challenge", "redirect_on_failure"},
            {"challenge", "link_url"},
            {"callback_url", "redirect_on_failure"},
            {"callback_url", "link_url"},
            {"redirect_on_failure", "link_url"},
        ]

        with self.http_con() as http_con:
            for partial_keyset in partial_keys:
                body = {
                    "email": email,
                    "challenge": challenge,
                    "callback_url": callback_url,
                    "redirect_on_failure": redirect_on_failure,
                    "link_url": link_url,
                }
                request_body = {
                    k: v for k, v in body.items() if k in partial_keyset
                }
                response_body, headers, status = self.http_con_request(
                    http_con,
                    method="POST",
                    path="magic-link/register",
                    body=json.dumps(request_body).encode(),
                    headers={"Content-Type": "application/json"},
                )

                # If redirect_on_failure is present, it redirects error there
                # (302)
                # otherwise it returns 400
                expected_status = (
                    302 if "redirect_on_failure" in partial_keyset else 400
                )
                self.assertEqual(
                    status,
                    expected_status,
                    f"Keys: {partial_keyset}, Got: {status}, "
                    f"Body: {response_body}",
                )
                if expected_status == 302:
                    location = headers.get("location")
                    self.assertTrue(location.startswith(redirect_on_failure))

            # Missing email in Magic Code flow
            await self.con.query(
                """
                CONFIGURE CURRENT DATABASE
                RESET ext::auth::MagicLinkProviderConfig;

                CONFIGURE CURRENT DATABASE
                INSERT ext::auth::MagicLinkProviderConfig {
                    verification_method := ext::auth::VerificationMethod.Code,
                };
            """
            )
            try:
                body, _, status = self.http_con_request(
                    http_con,
                    method="POST",
                    path="magic-link/email",
                    body=json.dumps({}).encode(),
                    headers={
                        "Content-Type": "application/json",
                        "Accept": "application/json",
                    },
                )
                self.assertEqual(status, 400, body)
            finally:
                await self.con.query(
                    """
                    CONFIGURE CURRENT DATABASE
                    RESET ext::auth::MagicLinkProviderConfig;
                    CONFIGURE CURRENT DATABASE
                    INSERT ext::auth::MagicLinkProviderConfig {};
                """
                )

    async def test_auto_signup(self):
        # 1. Auto Signup Enabled (Link)
        await self.con.query(
            """
            CONFIGURE CURRENT DATABASE
            RESET ext::auth::MagicLinkProviderConfig;

            CONFIGURE CURRENT DATABASE
            INSERT ext::auth::MagicLinkProviderConfig {
                auto_signup := true,
            };
            """
        )
        base_url = self.mock_net_server.get_base_url().rstrip("/")
        webhook_url = f"{base_url}/auto-signup-webhook"
        await self.con.query(
            """
            CONFIGURE CURRENT DATABASE
            INSERT ext::auth::WebhookConfig {
                url := <str>$url,
                events := {
                    ext::auth::WebhookEvent.IdentityCreated,
                    ext::auth::WebhookEvent.EmailFactorCreated,
                    ext::auth::WebhookEvent.MagicLinkRequested,
                },
            };
            """,
            url=webhook_url,
        )
        webhook_request = ("POST", base_url, "/auto-signup-webhook")
        self.mock_net_server.register_route_handler(*webhook_request)(("", 204))
        await self._wait_for_db_config("ext::auth::AuthConfig::webhooks")

        try:
            email = f"{uuid.uuid4()}@example.com"
            challenge = "test_auto_signup_challenge"
            callback_url = "https://example.com/app/auth/callback"
            redirect_on_failure = (
                "https://example.com/app/auth/magic-link-failure"
            )

            with self.http_con() as http_con:
                # Request magic link for non-existent user
                body, _, status = self.http_con_request(
                    http_con,
                    method="POST",
                    path="magic-link/email",
                    body=json.dumps(
                        {
                            "provider": "builtin::local_magic_link",
                            "email": email,
                            "challenge": challenge,
                            "callback_url": callback_url,
                            "redirect_on_failure": redirect_on_failure,
                        }
                    ).encode(),
                    headers={
                        "Content-Type": "application/json",
                        "Accept": "application/json",
                    },
                )

                self.assertEqual(status, 200, body)
                response_data = json.loads(body)
                self.assertEqual(response_data.get("email_sent"), email)
                self.assertEqual(response_data.get("signup"), "true")

                # Check Email
                link, _ = self._verify_email_file(email)
                self.assertIsNotNone(link)

                # Verify Webhooks
                async for tr in self.try_until_succeeds(
                    delay=2, timeout=120, ignore=(KeyError, AssertionError)
                ):
                    async with tr:
                        requests = self.mock_net_server.requests[
                            webhook_request
                        ]
                        self.assertEqual(len(requests), 3)

        finally:
            await self.con.query(
                "CONFIGURE CURRENT DATABASE RESET ext::auth::WebhookConfig"
            )
            await self.con.query(
                """
                CONFIGURE CURRENT DATABASE
                RESET ext::auth::MagicLinkProviderConfig;
                CONFIGURE CURRENT DATABASE
                INSERT ext::auth::MagicLinkProviderConfig {};
                """
            )

        # 2. Auto Signup Disabled (Link)
        await self.con.query(
            """
            CONFIGURE CURRENT DATABASE
            RESET ext::auth::MagicLinkProviderConfig;

            CONFIGURE CURRENT DATABASE
            INSERT ext::auth::MagicLinkProviderConfig {
                auto_signup := false,
            };
            """
        )
        try:
            email = f"{uuid.uuid4()}@example.com"
            with self.http_con() as http_con:
                body, _, status = self.http_con_request(
                    http_con,
                    method="POST",
                    path="magic-link/email",
                    body=json.dumps(
                        {
                            "provider": "builtin::local_magic_link",
                            "email": email,
                            "challenge": "challenge",
                            "callback_url": "https://cb.url",
                            "redirect_on_failure": "https://fail.url",
                        }
                    ).encode(),
                    headers={
                        "Content-Type": "application/json",
                        "Accept": "application/json",
                    },
                )
                self.assertEqual(status, 200, body)
                response_data = json.loads(body)
                self.assertEqual(response_data.get("email_sent"), email)
                self.assertNotIn("signup", response_data)

                # Verify user was NOT created
                existing_factor = await self.con.query(
                    "SELECT ext::auth::EmailFactor FILTER .email = <str>$email",
                    email=email,
                )
                self.assertEqual(len(existing_factor), 0)
        finally:
            await self.con.query(
                """
                CONFIGURE CURRENT DATABASE
                RESET ext::auth::MagicLinkProviderConfig;
                CONFIGURE CURRENT DATABASE
                INSERT ext::auth::MagicLinkProviderConfig {};
                """
            )

        # 3. Auto Signup Enabled (Code)
        await self.con.query(
            """
            CONFIGURE CURRENT DATABASE
            RESET ext::auth::MagicLinkProviderConfig;

            CONFIGURE CURRENT DATABASE
            INSERT ext::auth::MagicLinkProviderConfig {
                auto_signup := true,
                verification_method := ext::auth::VerificationMethod.Code,
            };
            """
        )
        try:
            email = f"{uuid.uuid4()}@example.com"
            with self.http_con() as http_con:
                body, _, status = self.http_con_request(
                    http_con,
                    method="POST",
                    path="magic-link/email",
                    body=json.dumps(
                        {
                            "provider": "builtin::local_magic_link",
                            "email": email,
                        }
                    ).encode(),
                    headers={
                        "Content-Type": "application/json",
                        "Accept": "application/json",
                    },
                )
                self.assertEqual(status, 200, body)
                response_data = json.loads(body)
                self.assertEqual(response_data.get("code"), "true")
                self.assertEqual(response_data.get("signup"), "true")

                # Verify user created
                existing_factor = await self.con.query(
                    "SELECT ext::auth::MagicLinkFactor "
                    "FILTER .email = <str>$email",
                    email=email,
                )
                self.assertEqual(len(existing_factor), 1)
        finally:
            await self.con.query(
                """
                CONFIGURE CURRENT DATABASE
                RESET ext::auth::MagicLinkProviderConfig;
                CONFIGURE CURRENT DATABASE
                INSERT ext::auth::MagicLinkProviderConfig {};
                """
            )

    async def test_otc_magic_link_flow(self):
        # Full OTC flow: Register -> Authenticate with Code
        await self.con.query(
            """
            CONFIGURE CURRENT DATABASE
            RESET ext::auth::MagicLinkProviderConfig;

            CONFIGURE CURRENT DATABASE
            INSERT ext::auth::MagicLinkProviderConfig {
                verification_method := ext::auth::VerificationMethod.Code,
            };
        """
        )

        try:
            email = f"{uuid.uuid4()}@example.com"
            verifier, challenge = self.generate_pkce_pair()
            callback_url = "https://example.com/app/auth/callback"

            with self.http_con() as http_con:
                # Register
                body, _, status = self.http_con_request(
                    http_con,
                    method="POST",
                    path="magic-link/register",
                    body=json.dumps({"email": email}).encode(),
                    headers={
                        "Content-Type": "application/json",
                        "Accept": "application/json",
                    },
                )
                self.assertEqual(status, 200)

                # Get Code
                _, otc_code = self._verify_email_file(email)
                self.assertIsNotNone(otc_code)

                # Authenticate
                form_data = {
                    "email": email,
                    "code": otc_code,
                    "challenge": challenge,
                    "callback_url": callback_url,
                }
                auth_body, auth_headers, auth_status = self.http_con_request(
                    http_con,
                    method="POST",
                    path="magic-link/authenticate",
                    body=urllib.parse.urlencode(form_data).encode(),
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded"
                    },
                )

                self.assertEqual(auth_status, 302, auth_body)
                location = auth_headers.get("location", "")
                self.assertTrue(location.startswith(callback_url))

                # Exchange Code
                parsed_url = urllib.parse.urlparse(location)
                query_params = urllib.parse.parse_qs(parsed_url.query)
                auth_code = query_params.get("code", [None])[0]

                token_body, _, token_status = self.http_con_request(
                    http_con,
                    params={
                        "code": auth_code,
                        "verifier": verifier,
                    },
                    method="GET",
                    path="token",
                    headers={"Content-Type": "application/json"},
                )
                self.assertEqual(token_status, 200)
                self.assertIn("auth_token", json.loads(token_body))

        finally:
            await self.con.query(
                """
                CONFIGURE CURRENT DATABASE
                RESET ext::auth::MagicLinkProviderConfig;
                CONFIGURE CURRENT DATABASE
                INSERT ext::auth::MagicLinkProviderConfig {};
            """
            )
