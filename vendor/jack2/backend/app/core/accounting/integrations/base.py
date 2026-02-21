import abc
import urllib.parse
from abc import abstractmethod
from uuid import UUID

from httpx import codes

from app.core.loggers import logger
from app.core.services.oauth.base import OAuthBasedIntegrationService
from app.core.services.oauth.exceptions import (
    OAuthIntegrationLoginFailedException,
    OAuthIntegrationLoginRequiredException,
    OAuthIntegrationRevokeTokenException,
    OAuthIntegrationValidationFailed,
)
from app.schemas.accounting import (
    IntegrationAccount,
    IntegrationCurrency,
    IntegrationInvoice,
    IntegrationTaxCode,
    IntegrationType,
    IntegrationVendor,
)
from app.schemas.accounting.schemas import (
    BaseSyncDocumentSchema,
    CreateVendorSchema,
    IntegrationOrganizationInfo,
)

from .cache_manager import AccountingIntegrationsCacheManager


class IntegrationBase(
    OAuthBasedIntegrationService, abc.ABC
):  # pylint: disable=too-many-public-methods
    platform_name: IntegrationType
    revoke_url: str
    RELEVANT_ACCOUNT_TYPES = ["ASSET", "EXPENSE", "LIABILITY", "REVENUE"]
    PAGINATED_RESOURCES = [
        "invoices",
        "accounts",
        "currencies",
        "tracking_categories",
        "vendors",
        "tax_codes",
        "bank_accounts",
    ]
    tenant_id: str | None = None
    tenant_name: str | None = None

    def __init__(
        self,
        company_id: UUID,
        user_id: UUID,
    ):
        self.company_id = company_id
        self.user_id = user_id
        self.accounting_integrations_cache_manager = (
            AccountingIntegrationsCacheManager()
        )
        self._auth_details = None
        self.referrer_url = None

    async def sync_invoice(
        self,
        invoice_details: BaseSyncDocumentSchema,
    ):
        await self._validate_invoice_data(invoice_details)
        return await self._create_invoice(invoice_details)

    async def sync_receipt(
        self,
        receipt_details: BaseSyncDocumentSchema,
    ):
        await self._validate_invoice_data(receipt_details)
        return await self._create_receipt(receipt_details)

    async def sync_credit_note(
        self, credit_note_details: BaseSyncDocumentSchema
    ):
        return await self._create_credit_note(credit_note_details)

    @abc.abstractmethod
    async def get_connected_client_id(self):
        raise NotImplementedError

    @abc.abstractmethod
    async def get_connected_client_name(self):
        raise NotImplementedError

    @abc.abstractmethod
    async def test_tenant_connection(self):
        raise NotImplementedError

    @abc.abstractmethod
    async def get_businesses(self, offset=0, limit=100, **kwargs):
        raise NotImplementedError  # pragma: no cover

    @abc.abstractmethod
    async def get_accounts(
        self, offset=0, limit=1000, **kwargs
    ) -> tuple[int, list[IntegrationAccount]]:  # pragma: no cover
        # get the accounts from the platform
        # offset and limit used to pagination results
        # kwargs used to add filtering if required
        raise NotImplementedError

    @abc.abstractmethod
    async def get_vendors(
        self, offset=0, limit=1000, **kwargs
    ) -> list[IntegrationVendor]:  # pragma: no cover
        # get the vendors from the platform
        # offset and limit used to pagination results
        # kwargs used to add filtering if required
        raise NotImplementedError

    @abc.abstractmethod
    async def get_invoices(
        self, offset=0, limit=1000, **kwargs
    ) -> list[IntegrationInvoice]:  # pragma: no cover
        # get the invoices from the platform
        # offset and limit used to pagination results
        # kwargs used to add filtering if required
        raise NotImplementedError

    @abc.abstractmethod
    async def get_tax_codes(
        self, offset=0, limit=1000, **kwargs
    ) -> list[IntegrationTaxCode]:  # pragma: no cover
        # get the tax codes from the platform
        raise NotImplementedError

    @abc.abstractmethod
    async def get_currencies(
        self, offset: int = 0, limit: int = 0
    ) -> list[IntegrationCurrency]:  # pragma: no cover
        # get the currencies from the platform
        raise NotImplementedError

    @abc.abstractmethod
    async def get_tax_rates(self):  # pragma: no cover
        raise NotImplementedError

    @abc.abstractmethod
    async def _create_invoice(self, invoice_data: BaseSyncDocumentSchema):
        # create an invoice on the platform
        raise NotImplementedError

    @abc.abstractmethod
    async def _create_receipt(
        self, receipt_input_data: BaseSyncDocumentSchema
    ):
        # create a receipt on the platform
        raise NotImplementedError

    @abc.abstractmethod
    async def _create_credit_note(
        self, credit_note_input_data: BaseSyncDocumentSchema
    ):
        raise NotImplementedError

    async def create_vendor(
        self, vendor_data: CreateVendorSchema
    ) -> IntegrationVendor:
        raise NotImplementedError

    async def get_vendor_by_name(self, name: str) -> IntegrationVendor:
        raise NotImplementedError

    @abc.abstractmethod
    async def add_attachment_to_document(
        self,
        invoice_id: str,
        file_obj: bytes,
        filename: str,
        document_type: str,
        *args,
        **kwargs,
    ):
        raise NotImplementedError

    @abc.abstractmethod
    async def get_tracking_categories(self, offset=0, limit=100, **kwargs):
        raise NotImplementedError

    @abc.abstractmethod
    async def _create_payment(self, payment_data):
        raise NotImplementedError

    @staticmethod
    async def _validate_invoice_data(
        invoice_data: BaseSyncDocumentSchema, *_, **__
    ):
        return invoice_data is not None

    @abstractmethod
    async def get_bank_accounts(self, offset=0, limit=100, **kwargs):
        raise NotImplementedError

    @abstractmethod
    async def get_organization_info(self) -> IntegrationOrganizationInfo:
        raise NotImplementedError

    async def handle_authorization_response(self, url: str) -> dict:
        url_bits = urllib.parse.urlparse(url)
        query_bits = urllib.parse.parse_qs(url_bits.query)

        state = self._validate_authorization_state(query_bits)

        self.company_id, self.user_id, _, self.referrer_url = (
            await self.validate_state(state)
        )

        code = self._validate_authorization_code(query_bits)

        # Exchange the authorization code for an access token
        session = await self._get_oauth_client(False)
        try:
            logger.info(
                "Trying to fetch token for company %s, user %s",
                self.company_id,
                self.user_id,
            )
            token = await session.fetch_token(
                self.token_url,
                client_secret=self.client_secret,
                code=code,
                access_type=self.access_type,
            )
            logger.info(
                "Fetched token successfully for company %s, user %s",
                self.company_id,
                self.user_id,
            )
        except Exception as e:
            raise OAuthIntegrationLoginFailedException(
                f"Token exchange failed. Exception {type(e)} occurred - {e}"
            ) from e

        await self._store_auth_details(token)
        return token

    async def _revoke(self):
        try:
            await self._revoke_token()
        except OAuthIntegrationRevokeTokenException as err:
            raise err
        finally:
            await self.delete_auth_from_cache()

    async def _revoke_token(self):  # pragma: no cover
        session = await self._get_oauth_client(True)
        try:
            revoke_response = await session.revoke_token(url=self.revoke_url)
            if codes.is_success(revoke_response.status_code):
                logger.info(
                    "%s platform token revoked",
                    str(self.platform_name),
                    extra={
                        "company_id": self.company_id,
                    },
                )
            else:
                logger.error(
                    "Failed to revoke token - %s",
                    str(revoke_response.text),
                    extra={"company_id": self.company_id},
                )
                raise OAuthIntegrationRevokeTokenException(
                    revoke_response.text
                )
        except Exception as e:
            logger.error(
                "Failed to revoke %s token - %s",
                str(e),
                str(self.platform_name),
                extra={"company_id": self.company_id},
            )
            await self.delete_auth_from_cache()
            raise OAuthIntegrationRevokeTokenException from e

    async def fetch_auth_details(self) -> dict:
        """
        Read auth info from cache or raise LoginRequired error
        if token is missed
        """
        if self._auth_details:
            return self._auth_details

        if auth_details := await self.accounting_integrations_cache_manager.fetch_auth_details(  # pylint: disable=line-too-long
            platform_name=self.platform_name.value,
            user_id=self.user_id,
            company_id=self.company_id,
        ):
            self._auth_details = auth_details
            return auth_details
        raise OAuthIntegrationLoginRequiredException(
            f"You are not connected to {self.platform_name.value} currently, please reconnect in order to continue your work"
        )

    async def does_auth_details_exist(self) -> bool:
        return bool(
            await self.accounting_integrations_cache_manager.fetch_auth_details(  # pylint: disable=line-too-long
                platform_name=self.platform_name.value,
                user_id=self.user_id,
                company_id=self.company_id,
            )
        )

    async def fetch_company_auth_details(self) -> list[dict]:
        return await self.accounting_integrations_cache_manager.fetch_company_auth_details(  # pylint: disable=line-too-long
            platform_name=self.platform_name.value,
            company_id=self.company_id,
        )

    async def delete_company_auth_details(self):
        return await self.accounting_integrations_cache_manager.delete_company_auth_details(  # pylint: disable=line-too-long
            platform_name=self.platform_name.value,
            company_id=self.company_id,
        )

    async def _store_auth_details(
        self, auth_details: dict, expiry=3600
    ) -> None:
        existing_integration_auth = await self.accounting_integrations_cache_manager.fetch_auth_details(  # pylint: disable=line-too-long
            platform_name=self.platform_name.value,
            user_id=self.user_id,
            company_id=self.company_id,
        )
        if existing_integration_auth:
            existing_integration_auth.update(auth_details)
            auth_details = existing_integration_auth

        await self.accounting_integrations_cache_manager.store_auth_details(
            platform_name=self.platform_name.value,
            user_id=self.user_id,
            company_id=self.company_id,
            auth_details=auth_details,
            expiry=expiry,
        )
        self._auth_details = auth_details

    async def update_auth_details(self, updated_auth_details: dict):
        auth_details = await self.fetch_auth_details()
        auth_details.update(updated_auth_details)
        await self._store_auth_details(auth_details)

    async def validate_state(self, state) -> tuple[str, str, str] | None:
        """
        Return tuple that contains the organization id, user id and platform
        """
        if state := await self.accounting_integrations_cache_manager.validate_and_extract_state(  # pylint: disable=line-too-long
            state
        ):
            return state
        raise OAuthIntegrationValidationFailed

    async def delete_auth_from_cache(self):
        self._auth_details = None
        return await self.accounting_integrations_cache_manager.delete_auth(
            platform_name=self.platform_name.value,
            user_id=self.user_id,
            company_id=self.company_id,
        )

    async def _cache_state_string(self, state: str):
        await self.accounting_integrations_cache_manager.generate_and_cache_state_string(  # pylint: disable=line-too-long
            company_id=self.company_id,
            user_id=self.user_id,
            platform_name=self.platform_name.value,
            state=state,
        )
