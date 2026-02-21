import abc
import datetime
import urllib.parse

from authlib.integrations.base_client.errors import OAuthError
from authlib.integrations.httpx_client import AsyncOAuth2Client
from authlib.oauth2 import OAuth2Error
from httpx import Response, codes

from app.core.loggers import logger

from .exceptions import (
    OAuthIntegrationAPICallFailed,
    OAuthIntegrationBaseException,
    OAuthIntegrationLoginRequiredException,
    OAuthIntegrationTooManyRequestsException,
    OAuthIntegrationValidationFailed,
)


class OAuthBasedIntegrationService(abc.ABC):
    platform_name: str
    authorization_url: str
    client_id: str
    client_secret: str
    scope: str
    redirect_url: str
    token_url: str
    refresh_url: str
    base_url: str
    access_type: str | None = None
    metadata: dict = {}
    grant_type: str = "client_credentials"

    def _register_oauth_hooks(self, _: AsyncOAuth2Client):
        """
        Register hooks that define how OAuth request body/headers/url should
        look and how OAuth response should be processed.
        No hooks registered by default
        """
        return

    def _register_oauth_auth_methods(self, _: AsyncOAuth2Client):
        """
        Register auth methods that extend client authenticate for token.
        No methods registered by default
        """
        return

    async def _get_oauth_client(self, require_auth: bool = True):
        if require_auth is True:
            auth_details = await self.fetch_auth_details()

            if auth_details is None:
                raise OAuthIntegrationLoginRequiredException(
                    f"You are not connected to {self.platform_name} currently, please reconnect in order to continue your work"  # pylint: disable=line-too-long
                )

            # calculate when the refresh token expires minus 5 minutes
            if refresh_token_expires_in := auth_details.get(
                "refresh_token_expires_in"
            ):
                refresh_expired = (
                    auth_details["expires_at"]
                    + refresh_token_expires_in
                    - (60 * 5)
                )
            else:
                refresh_expired = None

            if (
                refresh_expired
                and refresh_expired < datetime.datetime.now().timestamp()
            ):
                raise OAuthIntegrationLoginRequiredException

            async def token_updater(
                token, refresh_token
            ):  # pylint: disable=unused-argument
                await self._store_auth_details(token)

            oauth_client = AsyncOAuth2Client(
                # override defaults for poor Xero performance
                # default timeout 5.0
                timeout=30.0,
                client_id=self.client_id,
                token=auth_details,
                scope=self.scope,
                client_secret=self.client_secret,
                token_endpoint=self.refresh_url,
                update_token=token_updater,
                grant_type=self.grant_type,
                auth=None,
                **self.metadata,
            )
            self._register_oauth_hooks(oauth_client)
            self._register_oauth_auth_methods(oauth_client)
        else:
            oauth_client = AsyncOAuth2Client(
                # override defaults for poor Xero performance
                # default timeout 5.0
                timeout=30.0,
                client_id=self.client_id,
                scope=self.scope,
                redirect_uri=self.redirect_url,
                **self.metadata,
            )

        return oauth_client

    async def get_authorization_url(self):
        """
        Generate authorization URL with custom state.
        State is used to identify user and organization
        when handle authorization response
        """
        session = await self._get_oauth_client(
            require_auth=False,
        )
        authorization_url, state = session.create_authorization_url(
            self.authorization_url,
            access_type=self.access_type,
        )
        await self._cache_state_string(state)
        return authorization_url

    @staticmethod
    def _validate_authorization_state(query_bits: dict) -> str:
        if (
            "state" not in query_bits
            or len(query_bits["state"]) != 1
            and isinstance(query_bits["state"][0], str)
            or query_bits["state"][0] == ""
        ):
            raise OAuthIntegrationValidationFailed(
                "state not in correct format"
            )
        return query_bits["state"][0]

    @staticmethod
    def _validate_authorization_code(query_bits: dict) -> str:
        if (
            "code" not in query_bits
            or len(query_bits["code"]) != 1
            and isinstance(query_bits["code"][0], str)
            or query_bits["code"][0] == ""
        ):
            raise OAuthIntegrationValidationFailed(
                "code not in correct format"
            )
        return query_bits["code"][0]

    @abc.abstractmethod
    async def fetch_auth_details(self) -> dict:
        """
        Read token info from cache or raise LoginRequired error
        if token is missed
        """
        raise NotImplementedError

    @abc.abstractmethod
    async def _store_auth_details(
        self, auth_details: dict, expiry=3600
    ) -> None:
        raise NotImplementedError

    @abc.abstractmethod
    async def validate_state(self, state) -> tuple[str, str, str, str]:
        """
        Return tuple that contains the organization id, user id and platform
        """
        raise NotImplementedError

    @abc.abstractmethod
    async def delete_auth_from_cache(self):
        raise NotImplementedError

    @abc.abstractmethod
    async def _cache_state_string(self, state: str):
        raise NotImplementedError

    async def _revoke(self):
        # revoke the current token and connection
        await self.delete_auth_from_cache()

    async def delete_integration(self):
        await self._revoke()

    async def _make_call(
        self,
        method: str,
        url_path: str,
        headers: dict | None = None,
        body: dict | bytes | str | None = None,
        params: dict | None = None,
        json: dict | None = None,
        timeout: int = 60,
    ):
        """
        This method should be used when you want to make HTTP request
        :param method: HTTP method (GET, POST, PUT, DELETE, HEAD, etc)
        :param url_path: Relative URL path (e.g /v1/accounts)
        :param headers: Request headers
        :param body: Request body
        :param params: Query parameters
        :param json: Request data if Accept: application/json is used
        :param timeout: Request timeout
        :return: JSON response

        """
        try:
            session = await self._get_oauth_client()
            response = await session.request(
                method=method,
                url=urllib.parse.urljoin(self.base_url, url_path),
                headers=headers,
                data=body,
                timeout=timeout,
                params=params,
                json=json,
            )
            if response.status_code == codes.NOT_FOUND:
                raise OAuthIntegrationAPICallFailed(
                    f"Resource not found at {url_path} for {self.platform_name}"
                )
            if response.status_code == codes.TOO_MANY_REQUESTS:
                raise OAuthIntegrationTooManyRequestsException(
                    response=response,
                )
            if response.status_code == codes.UNAUTHORIZED:
                await self.delete_auth_from_cache()
                raise OAuthIntegrationLoginRequiredException(
                    f"You are not connected to {self.platform_name} currently, please reconnect in order to continue your work"  # pylint: disable=line-too-long
                )

            if response.status_code == codes.FORBIDDEN:
                await self.delete_auth_from_cache()
                raise OAuthIntegrationLoginRequiredException(
                    f"You are not connected to {self.platform_name} currently, please reconnect in order to continue your work"  # pylint: disable=line-too-long
                )

            if response.status_code == codes.BAD_REQUEST:
                self.process_bad_request_response(response)

            return response
        except (
            OAuthIntegrationLoginRequiredException,
            OAuthIntegrationTooManyRequestsException,
        ) as e:
            raise e
        except OAuthIntegrationBaseException as e:
            logger.error("OAuthIntegrationBaseException: %s", str(e))
            raise OAuthIntegrationAPICallFailed(str(e)) from e
        except (OAuth2Error, OAuthError) as e:
            logger.error("OAuthIntegrationAPICallFailed: %s", str(e))
            raise OAuthIntegrationAPICallFailed(str(e)) from e

    @staticmethod
    def process_bad_request_response(response: Response):
        logger.info(
            "Processing Bad Request response - %s",
            str(response),
            extra={"response_body": response.text},
        )
        raise OAuthIntegrationAPICallFailed(response.text)
