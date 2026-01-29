import json
import uuid
import urllib.parse
import datetime


from .base import BaseAuthTestCase, utcnow


class TestEmailPassword(BaseAuthTestCase):
    def _register_user(self, email, password="test_password", **kwargs):
        provider_name = "builtin::local_emailpassword"
        challenge = str(uuid.uuid4())

        form_data = {
            "provider": provider_name,
            "email": email,
            "password": password,
            "challenge": challenge,
            **kwargs,
        }
        form_data_encoded = urllib.parse.urlencode(form_data).encode()

        with self.http_con() as http_con:
            _, _, status = self.http_con_request(
                http_con,
                None,
                path="register",
                method="POST",
                body=form_data_encoded,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        return status, challenge

    async def test_register_form_flow(self):
        # Combined logic from form_01, form_02, json_02

        # 1. Basic Registration (form_01 logic)
        base_url = self.mock_net_server.get_base_url().rstrip("/")
        url = f"{base_url}/webhook-email-01"
        await self.con.query(
            """
            CONFIGURE CURRENT DATABASE
            INSERT ext::auth::WebhookConfig {
                url := <str>$url,
                events := {
                    ext::auth::WebhookEvent.IdentityCreated,
                    ext::auth::WebhookEvent.EmailFactorCreated,
                    ext::auth::WebhookEvent.EmailVerificationRequested,
                },
            };
            """,
            url=url,
        )
        webhook_request = ("POST", base_url, "/webhook-email-01")
        await self._wait_for_db_config("ext::auth::AuthConfig::webhooks")

        try:
            with self.http_con() as http_con:
                self.mock_net_server.register_route_handler(*webhook_request)(
                    ("", 204)
                )

                email = f"{uuid.uuid4()}@example.com"
                challenge = str(uuid.uuid4())
                form_data = {
                    "provider": "builtin::local_emailpassword",
                    "email": email,
                    "password": "test_password",
                    # Allowed redirect
                    "redirect_to": "https://example.com/app/path",
                    "challenge": challenge,
                }

                # Test Success
                _, headers, status = self.http_con_request(
                    http_con,
                    None,
                    path="register",
                    method="POST",
                    body=urllib.parse.urlencode(form_data).encode(),
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded"
                    },
                )
                self.assertEqual(status, 302)
                location = headers.get("location")
                self.assertIn("code=", location)

                # Verify DB
                identity = await self.con.query(
                    """
                    SELECT ext::auth::LocalIdentity
                    FILTER .<identity[is ext::auth::EmailPasswordFactor]
                        .email = <str>$email;
                    """,
                    email=email,
                )
                self.assertEqual(len(identity), 1)

                # Test JSON Registration (json_02 logic)
                email_json = f"{uuid.uuid4()}@example.com"
                json_data = {
                    "provider": "builtin::local_emailpassword",
                    "email": email_json,
                    "password": "test_password_json",
                    "challenge": str(uuid.uuid4()),
                }
                body, _, status = self.http_con_request(
                    http_con,
                    None,
                    path="register",
                    method="POST",
                    body=json.dumps(json_data).encode(),
                    headers={"Content-Type": "application/json"},
                )
                self.assertEqual(status, 201)
                self.assertIn("code", json.loads(body))

                # Test Validation (form_02 logic)
                # Invalid redirect
                form_data["redirect_to"] = "https://not-allowed.com"
                form_data["email"] = f"{uuid.uuid4()}@example.com"
                _, _, status = self.http_con_request(
                    http_con,
                    None,
                    path="register",
                    method="POST",
                    body=urllib.parse.urlencode(form_data).encode(),
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded"
                    },
                )
                self.assertEqual(status, 400)

        finally:
            await self.con.query(
                """
                CONFIGURE CURRENT DATABASE
                RESET ext::auth::WebhookConfig
                filter .url = <str>$url;
                """,
                url=url,
            )

    async def test_register_validation(self):
        with self.http_con() as http_con:
            # Missing Provider
            email = f"{uuid.uuid4()}@example.com"
            form_data = {
                "email": email,
                "password": "test_password",
                "challenge": str(uuid.uuid4()),
            }
            _, _, status = self.http_con_request(
                http_con,
                None,
                path="register",
                method="POST",
                body=urllib.parse.urlencode(form_data).encode(),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            self.assertEqual(status, 400)

            # Missing Password
            form_data = {
                "provider": "builtin::local_emailpassword",
                "email": email,
                "challenge": str(uuid.uuid4()),
            }
            _, _, status = self.http_con_request(
                http_con,
                None,
                path="register",
                method="POST",
                body=urllib.parse.urlencode(form_data).encode(),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            self.assertEqual(status, 400)

            # Missing Email
            form_data = {
                "provider": "builtin::local_emailpassword",
                "password": "test_password",
                "challenge": str(uuid.uuid4()),
            }
            _, _, status = self.http_con_request(
                http_con,
                None,
                path="register",
                method="POST",
                body=urllib.parse.urlencode(form_data).encode(),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            self.assertEqual(status, 400)

    async def test_register_no_smtp(self):
        await self.con.query(
            "CONFIGURE CURRENT DATABASE RESET current_email_provider_name;"
        )
        await self._wait_for_db_config(
            "cfg::current_email_provider_name", is_reset=True
        )
        try:
            status, _ = self._register_user(f"{uuid.uuid4()}@example.com")
            self.assertEqual(status, 201)
        finally:
            await self.con.query(
                "CONFIGURE CURRENT DATABASE "
                'SET current_email_provider_name := "email_hosting_is_easy";'
            )

    async def test_authenticate(self):
        email = f"{uuid.uuid4()}@example.com"
        password = "test_auth_password"

        # Register first
        status, _ = self._register_user(email, password)
        # 201 because no redirect_to provided in default _register_user,
        # and no SMTP check in this helper

        with self.http_con() as http_con:
            # Success
            auth_data = {
                "provider": "builtin::local_emailpassword",
                "email": email,
                "password": password,
                "challenge": str(uuid.uuid4()),
            }
            body, _, status = self.http_con_request(
                http_con,
                None,
                path="authenticate",
                method="POST",
                body=urllib.parse.urlencode(auth_data).encode(),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            self.assertEqual(status, 200)
            self.assertIn("code", json.loads(body))

            # Wrong Password
            auth_data["password"] = "wrong"
            _, _, status = self.http_con_request(
                http_con,
                None,
                path="authenticate",
                method="POST",
                body=urllib.parse.urlencode(auth_data).encode(),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            self.assertEqual(status, 403)

            # Redirect Flow on Failure
            auth_data["redirect_to"] = "https://example.com/app/home"
            auth_data["redirect_on_failure"] = "https://example.com/app/failure"
            _, headers, status = self.http_con_request(
                http_con,
                None,
                path="authenticate",
                method="POST",
                body=urllib.parse.urlencode(auth_data).encode(),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            self.assertEqual(status, 302)
            self.assertTrue(
                headers["location"].startswith(
                    "https://example.com/app/failure"
                )
            )

    async def test_forgot_password_flow(self):
        email = f"{uuid.uuid4()}@example.com"
        self._register_user(email, "old_password")

        with self.http_con() as http_con:
            # 1. Request Reset
            challenge = str(uuid.uuid4())
            form_data = {
                "provider": "builtin::local_emailpassword",
                "reset_url": "https://example.com/app/reset",
                "email": email,
                "challenge": challenge,
            }
            _, _, status = self.http_con_request(
                http_con,
                None,
                path="send-reset-email",
                method="POST",
                body=urllib.parse.urlencode(form_data).encode(),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            self.assertEqual(status, 200)

            # 2. Verify Email
            link, _ = self._verify_email_file(email)
            parsed_link = urllib.parse.urlparse(link)
            reset_token = urllib.parse.parse_qs(parsed_link.query)[
                "reset_token"
            ][0]

            # 3. Reset Password
            reset_data = {
                "provider": "builtin::local_emailpassword",
                "reset_token": reset_token,
                "password": "new_password",
            }
            body, _, status = self.http_con_request(
                http_con,
                None,
                path="reset-password",
                method="POST",
                body=urllib.parse.urlencode(reset_data).encode(),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            self.assertEqual(status, 200)

            # 4. Login with new password
            auth_data = {
                "provider": "builtin::local_emailpassword",
                "email": email,
                "password": "new_password",
                "challenge": str(uuid.uuid4()),
            }
            _, _, status = self.http_con_request(
                http_con,
                None,
                path="authenticate",
                method="POST",
                body=urllib.parse.urlencode(auth_data).encode(),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            self.assertEqual(status, 200)

    async def test_forgot_password_validation(self):
        with self.http_con() as http_con:
            # Invalid Reset URL domain
            form_data = {
                "provider": "builtin::local_emailpassword",
                "reset_url": "https://evil.com/reset",
                "email": f"{uuid.uuid4()}@example.com",
                "challenge": str(uuid.uuid4()),
            }
            _, _, status = self.http_con_request(
                http_con,
                None,
                path="send-reset-email",
                method="POST",
                body=urllib.parse.urlencode(form_data).encode(),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            self.assertEqual(status, 400)

    async def test_otc_flow(self):
        # Configure OTC
        await self.con.query("""
            CONFIGURE CURRENT DATABASE
            RESET ext::auth::EmailPasswordProviderConfig;
            CONFIGURE CURRENT DATABASE
            INSERT ext::auth::EmailPasswordProviderConfig {
                require_verification := true,
                verification_method := ext::auth::VerificationMethod.Code,
            };
        """)

        try:
            email = f"{uuid.uuid4()}@example.com"

            # 1. Register (Trigger OTC)
            with self.http_con() as http_con:
                form_data = {
                    "provider": "builtin::local_emailpassword",
                    "email": email,
                    "password": "password",
                    "challenge": str(uuid.uuid4()),
                }
                _, _, status = self.http_con_request(
                    http_con,
                    None,
                    path="register",
                    method="POST",
                    body=urllib.parse.urlencode(form_data).encode(),
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded"
                    },
                )
                self.assertEqual(status, 201)

            # 2. Get Code
            _, code = self._verify_email_file(email)
            self.assertIsNotNone(code)
            self.assertEqual(len(code), 6)

            # 3. Verify Code
            with self.http_con() as http_con:
                verify_data = {
                    "provider": "builtin::local_emailpassword",
                    "email": email,
                    "code": code,
                }
                _, _, status = self.http_con_request(
                    http_con,
                    None,
                    path="verify",
                    method="POST",
                    body=urllib.parse.urlencode(verify_data).encode(),
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded"
                    },
                )
                self.assertEqual(status, 204)

                # 4. Authenticate
                auth_data = {
                    "provider": "builtin::local_emailpassword",
                    "email": email,
                    "password": "password",
                    "challenge": str(uuid.uuid4()),
                }
                _, _, status = self.http_con_request(
                    http_con,
                    None,
                    path="authenticate",
                    method="POST",
                    body=urllib.parse.urlencode(auth_data).encode(),
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded"
                    },
                )
                self.assertEqual(status, 200)

        finally:
            await self.con.query("""
                CONFIGURE CURRENT DATABASE
                RESET ext::auth::EmailPasswordProviderConfig;
                CONFIGURE CURRENT DATABASE
                INSERT ext::auth::EmailPasswordProviderConfig {
                    require_verification := false,
                };
            """)

    async def test_otc_validation(self):
        # Configure OTC
        await self.con.query("""
            CONFIGURE CURRENT DATABASE
            RESET ext::auth::EmailPasswordProviderConfig;
            CONFIGURE CURRENT DATABASE
            INSERT ext::auth::EmailPasswordProviderConfig {
                require_verification := true,
                verification_method := ext::auth::VerificationMethod.Code,
            };
        """)

        base_url = self.mock_net_server.get_base_url().rstrip("/")
        url = f"{base_url}/otc-webhook-validation"
        await self.con.query(
            """
            CONFIGURE CURRENT DATABASE
            INSERT ext::auth::WebhookConfig {
                url := <str>$url,
                events := {
                    ext::auth::WebhookEvent.OneTimeCodeRequested,
                    ext::auth::WebhookEvent.OneTimeCodeVerified,
                },
            };
            """,
            url=url,
        )
        webhook_request = ("POST", base_url, "/otc-webhook-validation")
        self.mock_net_server.register_route_handler(*webhook_request)(("", 204))
        await self._wait_for_db_config("ext::auth::AuthConfig::webhooks")

        try:
            email = f"{uuid.uuid4()}@example.com"
            self._register_user(email, "password")

            with self.http_con() as http_con:
                # 1. Wrong Code
                verify_data = {
                    "provider": "builtin::local_emailpassword",
                    "email": email,
                    "code": "000000",
                }
                body, _, status = self.http_con_request(
                    http_con,
                    None,
                    path="verify",
                    method="POST",
                    body=urllib.parse.urlencode(verify_data).encode(),
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded"
                    },
                )
                self.assertEqual(status, 400)
                self.assertIn("error", json.loads(body))

                # Verify webhooks: OneTimeCodeRequested sent, but NOT
                # OneTimeCodeVerified
                async for tr in self.try_until_succeeds(
                    delay=2, timeout=120, ignore=(KeyError, AssertionError)
                ):
                    async with tr:
                        requests = self.mock_net_server.requests[
                            webhook_request
                        ]
                        self.assertEqual(len(requests), 1)
                        self.assertEqual(
                            json.loads(requests[0].body)["event_type"],
                            "OneTimeCodeRequested",
                        )

            # 2. Expired Code
            email_expired = f"{uuid.uuid4()}@example.com"
            self._register_user(email_expired, "password")

            # Manually expire the code in DB
            await self.con.query(
                """
                UPDATE ext::auth::OneTimeCode
                FILTER .factor[is ext::auth::EmailFactor].email = <str>$email
                SET { expires_at := <datetime>$expired }
            """,
                email=email_expired,
                expired=utcnow() - datetime.timedelta(minutes=5),
            )

            with self.http_con() as http_con:
                verify_data = {
                    "provider": "builtin::local_emailpassword",
                    "email": email_expired,
                    "code": "123456",  # Dummy code
                }
                # Let's get the code first
                _, code = self._verify_email_file(email_expired)
                verify_data["code"] = code

                body, _, status = self.http_con_request(
                    http_con,
                    None,
                    path="verify",
                    method="POST",
                    body=urllib.parse.urlencode(verify_data).encode(),
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded"
                    },
                )
                self.assertEqual(status, 400)
                self.assertIn("expired", json.loads(body)["error"].lower())

        finally:
            await self.con.query(
                """
                CONFIGURE CURRENT DATABASE
                RESET ext::auth::WebhookConfig
                filter .url = <str>$url;

                CONFIGURE CURRENT DATABASE
                RESET ext::auth::EmailPasswordProviderConfig;
                CONFIGURE CURRENT DATABASE
                INSERT ext::auth::EmailPasswordProviderConfig {
                    require_verification := false,
                };
            """,
                url=url,
            )
