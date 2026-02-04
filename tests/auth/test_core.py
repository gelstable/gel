import urllib.parse
import uuid
import json
import base64
import datetime
import os
import hashlib
import hmac

from edgedb import QueryAssertionError, ConstraintViolationError
from edb.server.protocol.auth_ext import otc

from .base import (
    BaseAuthTestCase,
    APP_NAME,
    LOGO_URL,
    BRAND_COLOR,
    b64_decode_padding,
    utcnow,
)


class TestCore(BaseAuthTestCase):
    SETUP = BaseAuthTestCase.SETUP + [
        """
        CREATE ROLE auth_user {
            SET password := 'secret';
            SET permissions := {
                ext::auth::perm::auth_read_user,
            }
        };
        """
    ]

    async def test_pkce_token_exchange(self):
        # Covers test_http_auth_ext_token_01
        base_url = self.mock_net_server.get_base_url().rstrip("/")
        webhook_request = (
            "POST",
            base_url,
            "/webhook-02",
        )
        url = f"{webhook_request[1]}/{webhook_request[2]}"
        signing_secret_key = str(uuid.uuid4())
        async with self.temporary_config(
            (
                f"""
                CONFIGURE CURRENT DATABASE
                INSERT ext::auth::WebhookConfig {{
                    url := <str>$url,
                    events := {{
                        ext::auth::WebhookEvent.IdentityAuthenticated,
                    }},
                    signing_secret_key := <str>$signing_secret_key,
                }};
                """,
                {
                    "url": url,
                    "signing_secret_key": signing_secret_key,
                },
            ),
            (
                """
                CONFIGURE CURRENT DATABASE
                RESET ext::auth::WebhookConfig filter .url = <str>$url;
                """,
                {"url": url},
            ),
            "ext::auth::AuthConfig::webhooks",
        ):
            with self.http_con() as http_con:
                self.mock_net_server.register_route_handler(*webhook_request)(
                    (
                        "",
                        204,
                    )
                )

                # Create a PKCE challenge and verifier
                verifier = base64.urlsafe_b64encode(os.urandom(43)).rstrip(b'=')
                challenge = base64.urlsafe_b64encode(
                    hashlib.sha256(verifier).digest()
                ).rstrip(b'=')
                pkce = await self.con.query_single(
                    """
                    select (
                        insert ext::auth::PKCEChallenge {
                            challenge := <str>$challenge,
                            auth_token := <str>$auth_token,
                            refresh_token := <str>$refresh_token,
                            id_token := <str>$id_token,
                            identity := (
                                insert ext::auth::Identity {
                                    issuer := "https://example.com",
                                    subject := "abcdefg",
                                }
                            ),
                        }
                    ) {
                        id,
                        challenge,
                        auth_token,
                        refresh_token,
                        id_token,
                        identity_id := .identity.id
                    }
                    """,
                    challenge=challenge.decode(),
                    auth_token="a_provider_token",
                    refresh_token="a_refresh_token",
                    id_token="an_id_token",
                )
                # Some other user
                other_user = await self.con.query_single(
                    """
                    insert ext::auth::Identity {
                        issuer := "https://example.com",
                        subject := "foobaz",
                    }
                    """
                )

                # Correct code, random verifier
                (_, _, wrong_verifier_status) = self.http_con_request(
                    http_con,
                    {
                        "code": pkce.id,
                        "verifier": base64.urlsafe_b64encode(os.urandom(43))
                        .rstrip(b"=")
                        .decode(),
                    },
                    path="token",
                )

                self.assertEqual(wrong_verifier_status, 403)

                # Correct code, correct verifier
                (
                    body,
                    _,
                    status,
                ) = self.http_con_request(
                    http_con,
                    {"code": pkce.id, "verifier": verifier.decode()},
                    path="token",
                )

                self.assertEqual(status, 200, body)
                body_json = json.loads(body)
                auth_token = body_json["auth_token"]

                self.assertEqual(
                    body_json,
                    {
                        "auth_token": auth_token,
                        "identity_id": str(pkce.identity_id),
                        "provider_token": "a_provider_token",
                        "provider_refresh_token": "a_refresh_token",
                        "provider_id_token": "an_id_token",
                    },
                )

                # Check that the client_token and ClientTokenIdentity works!
                await self.con.execute(
                    '''
                    set global ext::auth::client_token := <str>$0;
                    ''',
                    auth_token,
                )
                user = await self.con.query_single('''
                    select global ext::auth::ClientTokenIdentity { ** }
                ''')

                identities = await self.con.query('''
                    select ext::auth::Identity { ** }
                ''')

                await self.con.execute(
                    '''
                    reset global ext::auth::client_token
                    ''',
                )

                self.assertEqual(user.subject, "abcdefg")
                self.assertGreater(len(identities), 1)

                # Turn the real auth token into a fake auth token for
                # a different user.
                parts = auth_token.split('.')
                claims_bytes = b64_decode_padding(parts[1])
                claims = json.loads(claims_bytes)
                claims['sub'] = str(other_user.id)
                fake_claim_str = base64.urlsafe_b64encode(
                    json.dumps(claims).encode('utf-8')
                ).decode('ascii')
                parts[1] = fake_claim_str
                fake_auth_token = '.'.join(parts)

                # Try to use the fake auth token and make sure it fails!
                await self.con.execute(
                    '''
                    set global ext::auth::client_token := <str>$0;
                    ''',
                    fake_auth_token,
                )
                with self.assertRaisesRegex(
                    QueryAssertionError,
                    "signature mismatch",
                ):
                    await self.con.query_single('''
                        select global ext::auth::ClientTokenIdentity { ** }
                    ''')
                await self.con.execute(
                    '''
                    reset global ext::auth::client_token
                    ''',
                )

                # Now try with a non-superuser connection!
                con2 = await self.connect(
                    user='auth_user',
                    password='secret',
                )
                try:
                    await con2.execute(
                        '''
                        set global ext::auth::client_token := <str>$0;
                        ''',
                        auth_token,
                    )
                    user = await con2.query_single('''
                        select global ext::auth::ClientTokenIdentity { ** }
                    ''')
                    identities = await con2.query('''
                        select ext::auth::Identity { ** }
                    ''')
                    await con2.execute(
                        '''
                        reset global ext::auth::client_token
                        ''',
                    )

                    self.assertEqual(user.subject, "abcdefg")
                    self.assertEqual(len(identities), 1)

                finally:
                    await con2.aclose()

                # Check the webhooks
                async for tr in self.try_until_succeeds(
                    delay=2, timeout=120, ignore=(KeyError, AssertionError)
                ):
                    async with tr:
                        requests_for_webhook = self.mock_net_server.requests[
                            webhook_request
                        ]
                        self.assertEqual(len(requests_for_webhook), 1)

                webhook_request = requests_for_webhook[0]
                maybe_json_body = webhook_request.body
                self.assertIsNotNone(maybe_json_body)
                assert maybe_json_body is not None
                event_data = json.loads(maybe_json_body)
                self.assertEqual(
                    event_data["event_type"],
                    "IdentityAuthenticated",
                )
                self.assertEqual(
                    event_data["identity_id"], str(pkce.identity_id)
                )
                signature = requests_for_webhook[0].headers[
                    "x-ext-auth-signature-sha256"
                ]

                self.assertEqual(
                    signature,
                    hmac.new(
                        signing_secret_key.encode(),
                        requests_for_webhook[0].body.encode(),
                        hashlib.sha256,
                    ).hexdigest(),
                )

                # Correct code, correct verifier, already used PKCE
                (_, _, replay_attack_status) = self.http_con_request(
                    http_con,
                    {"code": pkce.id, "verifier": verifier.decode()},
                    path="token",
                )

                self.assertEqual(replay_attack_status, 403)

    async def test_pkce_token_validation(self):
        # Covers test_http_auth_ext_token_02 and 03
        with self.http_con() as http_con:
            # Too short: 32-octet -> 43-octet base64url
            verifier = base64.urlsafe_b64encode(os.urandom(31)).rstrip(b'=')
            (_, _, status) = self.http_con_request(
                http_con,
                {
                    "code": str(uuid.uuid4()),
                    "verifier": verifier.decode(),
                },
                path="token",
            )

            self.assertEqual(status, 400)

            # Too long: 96-octet -> 128-octet base64url
            verifier = base64.urlsafe_b64encode(os.urandom(97)).rstrip(b'=')
            (_, _, status) = self.http_con_request(
                http_con,
                {
                    "code": str(uuid.uuid4()),
                    "verifier": verifier.decode(),
                },
                path="token",
            )

            self.assertEqual(status, 400)

    async def test_ui_endpoints(self):
        # Covers test_http_auth_ext_ui_signin and static files
        with self.http_con() as http_con:
            challenge = (
                base64.urlsafe_b64encode(os.urandom(32)).rstrip(b'=').decode()
            )
            query_params = urllib.parse.urlencode({"challenge": challenge})

            body, _, status = self.http_con_request(
                http_con,
                path=f"ui/signin?{query_params}",
            )

            body_str = body.decode()

            self.assertIn(f"{APP_NAME[:100]}...", body_str)
            self.assertIn(LOGO_URL, body_str)
            self.assertIn(BRAND_COLOR, body_str)

            # Check for OAuth buttons
            self.assertIn("Sign in with Google", body_str)
            self.assertIn("Sign in with GitHub", body_str)
            self.assertIn("Sign in with My Generic OIDC Provider", body_str)
            self.assertEqual(status, 200)

            # Static files
            _, _, status = self.http_con_request(
                http_con,
                path="ui/_static/icon_github.svg",
            )

            self.assertEqual(status, 200)

    async def test_schema_introspection(self):
        # Covers test_edgeql_introspection_secret
        await self.assert_query_result(
            '''
            SELECT schema::Property { name }
            FILTER .secret AND .source.name = 'ext::auth::AuthConfig';
            ''',
            [{'name': 'auth_signing_key'}],
        )

    async def test_identity_cascade_delete(self):
        # Covers test_http_auth_ext_identity_delete_cascade_01, 02, 03

        # 1. LocalIdentity deletes Factors and PKCEChallenge
        result = await self.con.query_single(
            """
            with
                identity := (insert ext::auth::LocalIdentity {
                    issuer := "local",
                    subject := "",
                }),
                factor := (insert ext::auth::EmailPasswordFactor {
                    identity := identity,
                    email := "test@example.com",
                    password_hash := "abc123",
                }),
                pkce_challenge := (insert ext::auth::PKCEChallenge {
                    identity := identity,
                    challenge := "abc123",
                }),
            select identity;
            """,
        )

        await self.con.query(
            "delete <ext::auth::Identity><uuid>$identity_id;",
            identity_id=result.id,
        )

        # 2. Identity deletes associated objects
        result = await self.con.query_single(
            """
            with
                identity := (insert ext::auth::Identity {
                    issuer := "https://example.com",
                    subject := "abc123",
                }),
                pkce_challenge := (insert ext::auth::PKCEChallenge {
                    identity := identity,
                    challenge := "123abc",
                }),
            select identity;
            """,
        )

        await self.con.query(
            "delete <ext::auth::Identity><uuid>$identity_id;",
            identity_id=result.id,
        )

        # 3. WebAuthn LocalIdentity deletes associated WebAuthnFactor and
        # Challenge
        challenge = uuid.uuid4().bytes
        user_handle = uuid.uuid4().bytes
        credential_id = uuid.uuid4().bytes
        public_key = uuid.uuid4().bytes

        result = await self.con.query_single(
            """
            with
                user_handle := <bytes>$user_handle,
                credential_id := <bytes>$credential_id,
                public_key := <bytes>$public_key,
                challenge := <bytes>$challenge,
                identity := (insert ext::auth::LocalIdentity {
                    issuer := "local",
                    subject := "",
                }),
                factor := (insert ext::auth::WebAuthnFactor {
                    identity := identity,
                    user_handle := user_handle,
                    email := "test@example.com",
                    credential_id := credential_id,
                    public_key := public_key,
                }),
                challenge := (insert ext::auth::WebAuthnRegistrationChallenge {
                    challenge := challenge,
                    email := "test@example.com",
                    user_handle := user_handle,
                }),
                pkce_challenge := (insert ext::auth::PKCEChallenge {
                    identity := identity,
                    challenge := "abc123",
                }),
            select identity;
            """,
            user_handle=user_handle,
            credential_id=credential_id,
            public_key=public_key,
            challenge=challenge,
        )

        await self.con.query(
            "delete <ext::auth::LocalIdentity><uuid>$identity_id;",
            identity_id=result.id,
        )

    async def test_client_token_identity_card(self):
        await self.con.query_single(
            '''
            select global ext::auth::ClientTokenIdentity
        '''
        )

    async def test_otc_mechanics(self):
        # Covers test_http_auth_ext_otc_00, 06, 12, 13

        # otc_00: Schema mechanics
        email_config = await self.get_builtin_provider_config_by_name(
            "local_emailpassword"
        )
        self.assertEqual(str(email_config.verification_method), 'Link')

        magic_link_config = await self.get_builtin_provider_config_by_name(
            "local_magic_link"
        )
        self.assertEqual(str(magic_link_config.verification_method), 'Link')

        result = await self.con.query_single(
            """
            INSERT ext::auth::LocalIdentity {
                issuer := "test",
                subject := "test_user_123",
            };
        """
        )

        identity_id = result.id

        email_factor = await self.con.query_single(
            """
            INSERT ext::auth::EmailFactor {
                identity := <ext::auth::LocalIdentity><uuid>$identity_id,
                email := "test@example.com",
            };
        """,
            identity_id=identity_id,
        )

        expires_at = utcnow() + datetime.timedelta(minutes=10)
        otc_obj = await self.con.query_single(
            """
            with
                plaintext_code := b"test_hash_123",
                code_hash := ext::pgcrypto::digest(plaintext_code, 'sha256'),
                ONE_TIME_CODE := (
                    INSERT ext::auth::OneTimeCode {
                        code_hash := code_hash,
                        expires_at := <datetime>$expires_at,
                        factor := <ext::auth::Factor><uuid>$factor_id,
                    }
                ),
            select ONE_TIME_CODE { ** };
        """,
            expires_at=expires_at,
            factor_id=email_factor.id,
        )

        expected_hash = hashlib.sha256(b"test_hash_123").digest()
        self.assertEqual(otc_obj.code_hash, expected_hash)

        auth_attempt = await self.con.query_single(
            """
            with
                ATTEMPT := (
                    INSERT ext::auth::AuthenticationAttempt {
                        factor := <ext::auth::Factor><uuid>$factor_id,
                        attempt_type :=
                            ext::auth::AuthenticationAttemptType.OneTimeCode,
                        successful := false,
                    }
                ),
            select ATTEMPT { * };
        """,
            factor_id=email_factor.id,
        )

        self.assertEqual(str(auth_attempt.attempt_type), "OneTimeCode")
        self.assertFalse(auth_attempt.successful)
        self.assertIsNotNone(auth_attempt.created_at)
        self.assertIsNotNone(auth_attempt.modified_at)

        with self.assertRaises(ConstraintViolationError):
            await self.con.query(
                """
                with
                    plaintext_code := b"test_hash_123",
                    code_hash :=
                        ext::pgcrypto::digest(plaintext_code, 'sha256'),
                    ONE_TIME_CODE := (
                        INSERT ext::auth::OneTimeCode {
                            code_hash := code_hash,
                            expires_at := <datetime>$expires_at,
                            factor := <ext::auth::Factor><uuid>$factor_id,
                        }
                    ),
                select ONE_TIME_CODE { ** };
                """,
                expires_at=expires_at,
                factor_id=email_factor.id,
            )

        await self.con.query_single(
            """
            with
                ATTEMPT := (
                    INSERT ext::auth::AuthenticationAttempt {
                        factor := <ext::auth::Factor><uuid>$factor_id,
                        attempt_type :=
                            ext::auth::AuthenticationAttemptType.OneTimeCode,
                        successful := true,
                    }
                ),
            select ATTEMPT { * };
        """,
            factor_id=email_factor.id,
        )

        all_attempts = await self.con.query(
            """
            SELECT ext::auth::AuthenticationAttempt { * }
            FILTER .factor.id = <uuid>$factor_id
            ORDER BY .created_at;
        """,
            factor_id=email_factor.id,
        )

        self.assertEqual(len(all_attempts), 2)
        self.assertFalse(all_attempts[0].successful)
        self.assertTrue(all_attempts[1].successful)

        # otc_06: Expired code verification
        identity = await self.con.query_single(
            """
            INSERT ext::auth::LocalIdentity {
                issuer := "test",
                subject := "test_user_otc_expired",
            };
        """
        )

        email_factor = await self.con.query_single(
            """
            INSERT ext::auth::EmailFactor {
                identity := <ext::auth::LocalIdentity><uuid>$identity_id,
                email := "test_otc_expired@example.com",
            };
        """,
            identity_id=identity.id,
        )

        expired_time = utcnow() - datetime.timedelta(minutes=5)
        code_hash = otc.hash_code("123456")

        expired_otc = await self.con.query_single(
            """
            INSERT ext::auth::OneTimeCode {
                factor := <ext::auth::Factor><uuid>$factor_id,
                code_hash := <bytes>$code_hash,
                expires_at := <datetime>$expires_at,
            };
        """,
            factor_id=email_factor.id,
            code_hash=code_hash,
            expires_at=expired_time,
        )

        with self.http_con() as http_con:
            form_data = {
                "email": "test_otc_expired@example.com",
                "code": "123456",
                "challenge": "test_challenge_expired",
                "callback_url": "https://example.com/app/auth/callback",
            }
            form_data_encoded = urllib.parse.urlencode(form_data).encode()

            auth_body, auth_headers, auth_status = self.http_con_request(
                http_con,
                method="POST",
                path="magic-link/authenticate",
                body=form_data_encoded,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        self.assertEqual(
            auth_status, 400, f"Expected 400, got {auth_status}: {auth_body}"
        )
        error_data = json.loads(auth_body)
        self.assertEqual(error_data.get("error"), "Code has expired")

        deleted_otc = await self.con.query_single(
            "SELECT ext::auth::OneTimeCode { ** } FILTER .id = <uuid>$otc_id",
            otc_id=expired_otc.id,
        )
        self.assertIsNone(deleted_otc)

        # otc_12: Expired cleanup during any verification
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

        email = f"{uuid.uuid4()}@example.com"
        callback_url = "https://example.com/app/auth/callback"
        error_url = "https://example.com/app/auth/error"
        verifier, challenge = self.generate_pkce_pair()

        with self.http_con() as http_con:
            register_body, register_headers, register_status = (
                self.http_con_request(
                    http_con,
                    method="POST",
                    path="magic-link/register",
                    body=json.dumps(
                        {
                            "provider": "builtin::local_magic_link",
                            "email": email,
                            "challenge": challenge,
                            "callback_url": callback_url,
                            "redirect_on_failure": error_url,
                        }
                    ).encode(),
                    headers={
                        "Content-Type": "application/json",
                        "Accept": "application/json",
                    },
                )
            )
            self.assertEqual(register_status, 200, register_body)

            factor = await self.con.query_required_single(
                """
                select assert_exists((
                    SELECT ext::auth::EmailFactor { id }
                    FILTER .email = <str>$email
                    limit 1
                ))
                """,
                email=email,
            )

            expired_time = utcnow() - datetime.timedelta(minutes=5)
            for i in range(3):
                await self.con.query(
                    """
                    INSERT ext::auth::OneTimeCode {
                        factor := <ext::auth::Factor><uuid>$factor_id,
                        code_hash := <bytes>$code_hash,
                        expires_at := <datetime>$expires_at,
                    };
                """,
                    factor_id=factor.id,
                    code_hash=otc.hash_code(f"12345{i}"),
                    expires_at=expired_time,
                )

            expired_codes_query = """
                SELECT count(
                    SELECT ext::auth::OneTimeCode
                    FILTER .factor.id = <uuid>$factor_id
                )
            """
            expired_count = await self.con.query_single(
                expired_codes_query,
                factor_id=factor.id,
            )
            self.assertEqual(expired_count, 4)

            form_data = {
                "email": email,
                "code": "999999",
                "challenge": challenge,
                "callback_url": callback_url,
            }
            form_data_encoded = urllib.parse.urlencode(form_data).encode()

            self.http_con_request(
                http_con,
                method="POST",
                path="magic-link/authenticate",
                body=form_data_encoded,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )

            remaining_count = await self.con.query_single(
                expired_codes_query,
                factor_id=factor.id,
            )
            self.assertEqual(remaining_count, 1)

        # otc_13: Rate limiting
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

        email = f"{uuid.uuid4()}@example.com"
        callback_url = "https://example.com/app/auth/callback"
        error_url = "https://example.com/app/auth/error"
        verifier, challenge = self.generate_pkce_pair()

        with self.http_con() as http_con:
            register_body, register_headers, register_status = (
                self.http_con_request(
                    http_con,
                    method="POST",
                    path="magic-link/register",
                    body=json.dumps(
                        {
                            "provider": "builtin::local_magic_link",
                            "email": email,
                            "callback_url": callback_url,
                            "redirect_on_failure": error_url,
                            "challenge": challenge,
                        }
                    ).encode(),
                    headers={
                        "Content-Type": "application/json",
                        "Accept": "application/json",
                    },
                )
            )
            self.assertEqual(register_status, 200, register_body)

            for i in range(5):
                form_data = {
                    "email": email,
                    "code": f"00000{i}",
                    "challenge": challenge,
                    "callback_url": callback_url,
                }
                form_data_encoded = urllib.parse.urlencode(form_data).encode()

                body, headers, status = self.http_con_request(
                    http_con,
                    method="POST",
                    path="magic-link/authenticate",
                    body=form_data_encoded,
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Accept": "application/json",
                    },
                )
                self.assertEqual(status, 400, body)
                self.assertIn("invalid code", body.decode().lower())

            form_data = {
                "email": email,
                "code": "000006",
                "challenge": challenge,
                "callback_url": callback_url,
            }
            form_data_encoded = urllib.parse.urlencode(form_data).encode()

            body, headers, status = self.http_con_request(
                http_con,
                method="POST",
                path="magic-link/authenticate",
                body=form_data_encoded,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept": "application/json",
                },
            )
            self.assertEqual(status, 400, body)
            self.assertIn("attempts exceeded", body.decode().lower())
