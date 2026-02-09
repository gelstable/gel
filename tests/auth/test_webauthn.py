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

import base64
import json
import urllib.parse
import uuid

from edgedb import QueryAssertionError

from .base import BaseAuthTestCase, APP_NAME


class TestWebAuthn(BaseAuthTestCase):
    async def test_webauthn_register_options(self):
        with self.http_con() as http_con:
            email = f"{uuid.uuid4()}@example.com"
            query_params = urllib.parse.urlencode({"email": email})

            body, headers, status = self.http_con_request(
                http_con,
                path=f"webauthn/register/options?{query_params}",
            )

            body_json = json.loads(body.decode())
            self.assertEqual(status, 200)

            # Check the structure of the PublicKeyCredentialCreationOptions
            self.assertIn("rp", body_json)
            self.assertIn("user", body_json)
            self.assertIn("challenge", body_json)
            self.assertIn("pubKeyCredParams", body_json)
            self.assertIn("timeout", body_json)
            self.assertIn("excludeCredentials", body_json)
            self.assertIn("attestation", body_json)

            self.assertIsInstance(body_json["rp"], dict)
            self.assertIn("name", body_json["rp"])
            self.assertEqual(body_json["rp"]["name"], f"{APP_NAME[:100]}...")
            self.assertIn("id", body_json["rp"])
            self.assertEqual(body_json["rp"]["id"], "example.com")

            self.assertIsInstance(body_json["user"], dict)
            self.assertIn("id", body_json["user"])
            self.assertIsInstance(body_json["user"]["id"], str)
            self.assertIn("name", body_json["user"])
            self.assertEqual(body_json["user"]["name"], email)
            self.assertIn("displayName", body_json["user"])
            self.assertEqual(body_json["user"]["displayName"], email)

            self.assertIsInstance(body_json["pubKeyCredParams"], list)
            self.assertTrue(len(body_json["pubKeyCredParams"]) > 0)
            for param in body_json["pubKeyCredParams"]:
                self.assertIn("type", param)
                self.assertEqual(param["type"], "public-key")
                self.assertIn("alg", param)
                self.assertIsInstance(param["alg"], int)

            self.assertEqual(body_json["timeout"], 60000)

            self.assertIsInstance(body_json["excludeCredentials"], list)

            self.assertEqual(body_json["attestation"], "none")

            challenge_bytes = base64.urlsafe_b64decode(
                f'{body_json["challenge"]}==='
            )
            user_handle = base64.urlsafe_b64decode(
                f'{body_json["user"]["id"]}==='
            )
            user_handle_cookie = self.maybe_get_cookie_value(
                headers, "edgedb-webauthn-registration-user-handle"
            )
            user_handle_cookie_value = base64.urlsafe_b64decode(
                f'{user_handle_cookie}==='
            )
            self.assertEqual(user_handle_cookie_value, user_handle)

            self.assertTrue(
                await self.con.query_single(
                    '''
                    SELECT EXISTS (
                        SELECT ext::auth::WebAuthnRegistrationChallenge
                        filter .challenge = <bytes>$challenge
                        AND .email = <str>$email
                        AND .user_handle = <bytes>$user_handle
                    )
                    ''',
                    challenge=challenge_bytes,
                    email=email,
                    user_handle=user_handle,
                )
            )

    async def test_webauthn_register_options_existing_user(self):
        email = f"{uuid.uuid4()}@example.com"
        existing_user_handle = uuid.uuid4().bytes

        # Insert two existing WebAuthnFactors for the email
        await self.con.query_single(
            """
            with
                email := <str>$email,
                user_handle := <bytes>$user_handle,
                credential_one := <bytes>$credential_one,
                public_key_one := <bytes>$public_key_one,
                credential_two := <bytes>$credential_two,
                public_key_two := <bytes>$public_key_two,
                factor_one := (insert ext::auth::WebAuthnFactor {
                    email := email,
                    user_handle := user_handle,
                    credential_id := credential_one,
                    public_key := public_key_one,
                    identity := (insert ext::auth::LocalIdentity {
                        issuer := "local",
                        subject := "",
                    }),
                }),
                factor_two := (insert ext::auth::WebAuthnFactor {
                    email := email,
                    user_handle := user_handle,
                    credential_id := credential_two,
                    public_key := public_key_two,
                    identity := (insert ext::auth::LocalIdentity {
                        issuer := "local",
                        subject := "",
                    }),
                }),
            select true;
            """,
            email=email,
            user_handle=existing_user_handle,
            credential_one=uuid.uuid4().bytes,
            public_key_one=uuid.uuid4().bytes,
            credential_two=uuid.uuid4().bytes,
            public_key_two=uuid.uuid4().bytes,
        )

        with self.http_con() as http_con:
            body, _, status = self.http_con_request(
                http_con,
                path=f"webauthn/register/options?email={email}",
            )

            self.assertEqual(status, 200)

            body_json = json.loads(body)
            self.assertIn("user", body_json)
            self.assertIn("id", body_json["user"])
            user_id_decoded = base64.urlsafe_b64decode(
                f'{body_json["user"]["id"]}==='
            )

            self.assertEqual(user_id_decoded, existing_user_handle)

    async def test_webauthn_constraints(self):
        email = f"{uuid.uuid4()}@example.com"

        user_handle_one = uuid.uuid4().bytes
        credential_id_one = uuid.uuid4().bytes
        public_key_one = uuid.uuid4().bytes

        user_handle_two = uuid.uuid4().bytes
        credential_id_two = uuid.uuid4().bytes
        public_key_two = uuid.uuid4().bytes

        with self.assertRaisesRegex(
            QueryAssertionError,
            "user_handle must be the same for a given email",
        ):
            await self.con.execute(
                """
                with
                    factor_one := (insert ext::auth::WebAuthnFactor {
                        email := <str>$email,
                        user_handle := <bytes>$user_handle_one,
                        credential_id := <bytes>$credential_id_one,
                        public_key := <bytes>$public_key_one,
                        identity := (insert ext::auth::LocalIdentity {
                            issuer := "local",
                            subject := "",
                        }),
                    }),
                    factor_two := (insert ext::auth::WebAuthnFactor {
                        email := <str>$email,
                        user_handle := <bytes>$user_handle_two,
                        credential_id := <bytes>$credential_id_two,
                        public_key := <bytes>$public_key_two,
                        identity := (insert ext::auth::LocalIdentity {
                            issuer := "local",
                            subject := "",
                        }),
                    })
                select true;
                """,
                email=email,
                user_handle_one=user_handle_one,
                credential_id_one=credential_id_one,
                public_key_one=public_key_one,
                user_handle_two=user_handle_two,
                credential_id_two=credential_id_two,
                public_key_two=public_key_two,
            )

    async def test_webauthn_authenticate_options(self):
        with self.http_con() as http_con:
            email = f"{uuid.uuid4()}@example.com"
            user_handle = uuid.uuid4().bytes
            credential_id = uuid.uuid4().bytes
            public_key = uuid.uuid4().bytes

            await self.con.query_single(
                """
                with identity := (insert ext::auth::LocalIdentity {
                    issuer := "local",
                    subject := "",
                })
                INSERT ext::auth::WebAuthnFactor {
                    email := <str>$email,
                    user_handle := <bytes>$user_handle,
                    credential_id := <bytes>$credential_id,
                    public_key := <bytes>$public_key,
                    identity := identity,
                };
                """,
                email=email,
                user_handle=user_handle,
                credential_id=credential_id,
                public_key=public_key,
            )

            body, _headers, status = self.http_con_request(
                http_con,
                path=f"webauthn/authenticate/options?email={email}",
            )

            self.assertEqual(status, 200)

            body_json = json.loads(body)
            self.assertIn("challenge", body_json)
            self.assertIsInstance(body_json["challenge"], str)
            self.assertIn("rpId", body_json)
            self.assertIsInstance(body_json["rpId"], str)
            self.assertIn("timeout", body_json)
            self.assertIsInstance(body_json["timeout"], int)
            self.assertIn("allowCredentials", body_json)
            self.assertIsInstance(body_json["allowCredentials"], list)
            allow_credentials = body_json["allowCredentials"]
            self.assertTrue(
                all(
                    "type" in cred and "id" in cred
                    for cred in allow_credentials
                ),
                "Each credential should have 'type' and 'id' keys",
            )
            self.assertIn(
                base64.urlsafe_b64encode(credential_id).rstrip(b"=").decode(),
                [cred["id"] for cred in allow_credentials],
                (
                    "The generated credential_id should be in the "
                    "'allowCredentials' list"
                ),
            )

            challenge_bytes = base64.urlsafe_b64decode(
                f'{body_json["challenge"]}==='
            )
            self.assertTrue(
                await self.con.query_single(
                    '''
                    SELECT EXISTS (
                        SELECT ext::auth::WebAuthnAuthenticationChallenge
                        filter .challenge = <bytes>$challenge
                        AND any(
                            .factors.email = <str>$email
                            AND .factors.user_handle = <bytes>$user_handle
                        )
                    )
                    ''',
                    challenge=challenge_bytes,
                    email=email,
                    user_handle=user_handle,
                )
            )

    async def test_webauthn_resend_verification(self):
        with self.http_con() as http_con:
            # Register a new user
            provider_config = await self.get_builtin_provider_config_by_name(
                "local_webauthn"
            )
            provider_name = provider_config.name
            email = f"{uuid.uuid4()}@example.com"
            credential_one = uuid.uuid4().bytes
            credential_two = uuid.uuid4().bytes

            await self.con.query_single(
                """
                with
                    email := <str>$email,
                    user_handle := <bytes>$user_handle,
                    credential_one := <bytes>$credential_one,
                    public_key_one := <bytes>$public_key_one,
                    credential_two := <bytes>$credential_two,
                    public_key_two := <bytes>$public_key_two,
                    factor_one := (insert ext::auth::WebAuthnFactor {
                        email := email,
                        user_handle := user_handle,
                        credential_id := credential_one,
                        public_key := public_key_one,
                        identity := (insert ext::auth::LocalIdentity {
                            issuer := "local",
                            subject := "",
                        }),
                    }),
                    factor_two := (insert ext::auth::WebAuthnFactor {
                        email := email,
                        user_handle := user_handle,
                        credential_id := credential_two,
                        public_key := public_key_two,
                        identity := (insert ext::auth::LocalIdentity {
                            issuer := "local",
                            subject := "",
                        }),
                    }),
                select true;
                """,
                email=email,
                user_handle=uuid.uuid4().bytes,
                credential_one=credential_one,
                public_key_one=uuid.uuid4().bytes,
                credential_two=credential_two,
                public_key_two=uuid.uuid4().bytes,
            )

            # Resend verification email with credential_id
            resend_data = {
                "provider": provider_name,
                "credential_id": base64.b64encode(credential_one).decode(),
            }
            resend_data_encoded = urllib.parse.urlencode(resend_data).encode()

            _, _, status = self.http_con_request(
                http_con,
                None,
                path="resend-verification-email",
                method="POST",
                body=resend_data_encoded,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )

            self.assertEqual(status, 200)

            link, _ = self._verify_email_file(email)
            assert link is not None
            verify_url = urllib.parse.urlparse(link)
            search_params = urllib.parse.parse_qs(verify_url.query)
            verification_token = search_params.get(
                "verification_token", [None]
            )[0]
            assert verification_token is not None

            # Resend verification email with the verification token
            resend_data = {
                "provider": provider_name,
                "verification_token": verification_token,
            }
            resend_data_encoded = urllib.parse.urlencode(resend_data).encode()

            body, _, status = self.http_con_request(
                http_con,
                None,
                path="resend-verification-email",
                method="POST",
                body=resend_data_encoded,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )

            self.assertEqual(status, 200, body)

            # Resend verification email with email
            resend_data = {
                "provider": provider_name,
                "email": email,
            }
            resend_data_encoded = urllib.parse.urlencode(resend_data).encode()

            _, _, status = self.http_con_request(
                http_con,
                None,
                path="resend-verification-email",
                method="POST",
                body=resend_data_encoded,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )

            self.assertEqual(status, 400)

    async def test_webauthn_invalid_request(self):
        with self.http_con() as http_con:
            email = f"{uuid.uuid4()}@example.com"
            body, _, status = self.http_con_request(
                http_con,
                method="GET",
                path=f"webauthn/register/options?email={email}",
            )
            self.assertEqual(status, 200, body.decode())
            body_json = json.loads(body)
            self.assertIn("user", body_json)
            self.assertIn("id", body_json["user"])
            user_handle = body_json["user"]["id"]
            credentials = {
                "rawId": base64.urlsafe_b64encode(uuid.uuid4().bytes)
                .rstrip(b"=")
                .decode(),
                "response": {
                    "clientDataJSON": base64.urlsafe_b64encode(
                        uuid.uuid4().bytes
                    )
                    .rstrip(b"=")
                    .decode(),
                    "authenticatorData": base64.urlsafe_b64encode(
                        uuid.uuid4().bytes
                    )
                    .rstrip(b"=")
                    .decode(),
                    "signature": base64.urlsafe_b64encode(uuid.uuid4().bytes)
                    .rstrip(b"=")
                    .decode(),
                    "userHandle": user_handle,
                },
            }

            body, _, status = self.http_con_request(
                http_con,
                method="POST",
                headers={
                    "Content-Type": "application/json",
                },
                body=json.dumps(
                    {
                        "provider": "builtin::local_webauthn",
                        "email": email,
                        "user_handle": user_handle,
                        "credentials": credentials,
                        "verify_url": "https://example.com/app/auth/verify",
                        "challenge": "some_pkce_challenge",
                    }
                ).encode(),
                path="webauthn/register",
            )
            self.assertEqual(status, 400, body.decode())
