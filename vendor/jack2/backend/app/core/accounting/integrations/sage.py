import urllib.parse

from authlib.common.urls import url_decode, url_encode
from authlib.integrations.httpx_client import AsyncOAuth2Client

from app.core.accounting.exceptions import (
    AccountingIntegrationFailedToCreateInvoiceException,
    AccountingIntegrationFailedToCreatePaymentException,
    AccountingIntegrationFailedToCreateVendorException,
    AccountingIntegrationTenantMissedException,
    AccountingIntegrationTooManyRequestsException,
)
from app.core.config import settings
from app.core.decorators import execution_time_tracking
from app.core.loggers import logger
from app.core.services.oauth.exceptions import (
    OAuthIntegrationBaseException,
    OAuthIntegrationLoginRequiredException,
    OAuthIntegrationTooManyRequestsException,
)
from app.schemas.accounting import (
    BaseSyncDocumentSchema,
    IntegrationAccount,
    IntegrationBusiness,
    IntegrationCurrency,
    IntegrationInvoice,
    IntegrationLineItem,
    IntegrationOrganizationInfo,
    IntegrationTaxCode,
    IntegrationType,
    IntegrationVendor,
    SageContactTypes,
    SageSyncInvoiceSchema,
)
from app.schemas.accounting.schemas import (
    CreateVendorSchema,
    IntegrationTrackingCategoryOptionSchema,
    IntegrationTrackingCategorySchema,
    SageCreatePaymentSchema,
)

from .base import IntegrationBase


class SageIntegration(IntegrationBase):
    platform_name = IntegrationType.SAGE

    authorization_url = str(settings.SAGE_AUTHORIZATION_URL)
    scope = settings.SAGE_SCOPE
    token_url = str(settings.SAGE_TOKEN_URL)
    revoke_url = str(settings.SAGE_REVOKE_TOKEN_URL)
    refresh_url = str(settings.SAGE_TOKEN_URL)
    base_url = str(settings.SAGE_BASE_URL)
    redirect_url = urllib.parse.urljoin(
        str(settings.DOMAIN), "/v2/integrations/callback/sage"
    )
    client_id = settings.SAGE_CLIENT_ID
    client_secret = settings.SAGE_CLIENT_SECRET
    tenant_id: int | None = None
    tenant_name: str | None = None

    INVOICE_PAYMENT_STATUS_MAPPING = {
        "DRAFT": "DRAFT",
        "AWAITING_PAYMENT": "UNPAID",
        # We should record payment to mark invoice as paid
        "PAID": "UNPAID",
    }

    @property
    def headers(self):
        if not self.tenant_id:
            logger.error(
                "Tenant id was not set correctly for SageIntegrationClient"
            )
            raise AccountingIntegrationTenantMissedException
        return {"X-Business": self.tenant_id}

    async def get_connected_client_id(self):
        await self._init_business_id()
        return self.tenant_id

    async def get_connected_client_name(self):
        await self._init_business_name()
        return self.tenant_name

    def _register_oauth_hooks(self, session: AsyncOAuth2Client):
        def refresh_token_body_request_hook(
            url: str, headers: dict, body: str
        ):
            body = dict(url_decode(body))
            body.update(
                {
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                }
            )
            return url, headers, url_encode(body.items())

        session.register_compliance_hook(
            hook_type="refresh_token_request",
            hook=refresh_token_body_request_hook,
        )
        session.register_compliance_hook(
            hook_type="revoke_token_request",
            hook=refresh_token_body_request_hook,
        )

    def _register_oauth_auth_methods(self, session: AsyncOAuth2Client):
        session.register_client_auth_method(
            auth=("client_secret_basic", "none")
        )

    async def _init_business_id(self):
        """Read tenant ID from Xero auth details"""
        if self.tenant_id:
            return self.tenant_id

        auth_details = await self.fetch_auth_details()
        if business_id := auth_details.get("business_id"):
            self.tenant_id = business_id
            return business_id
        raise OAuthIntegrationLoginRequiredException

    async def _init_business_name(self):
        """Read tenant name from Sage auth details"""
        if self.tenant_name:
            return self.tenant_name

        auth_details = await self.fetch_auth_details()
        if business_name := auth_details.get("business_name"):
            self.tenant_name = business_name
            return business_name
        raise OAuthIntegrationLoginRequiredException

    async def _store_auth_details(
        self, auth_details: dict, expiry: int = 3600
    ) -> None:
        expiry = auth_details["refresh_token_expires_in"]
        return await super()._store_auth_details(
            auth_details=auth_details, expiry=expiry
        )

    @execution_time_tracking(platform=IntegrationType.SAGE)
    async def get_businesses(
        self, offset=0, limit=100, **kwargs
    ) -> list[IntegrationBusiness]:
        logger.info(
            "Retrieving businesses (offset=%s, limit=%s) from %s for company_id=%s",
            offset,
            limit,
            self.platform_name.value,
            self.company_id,
        )

        page = (offset // limit) + 1
        businesses = []
        try:
            businesses_response = await self._make_call(
                "get",
                url_path="/v3.1/businesses",
                params={
                    "page": page,
                    "items_per_page": limit,
                    "attributes": "all",
                },
            )
        except OAuthIntegrationTooManyRequestsException as err:
            raise AccountingIntegrationTooManyRequestsException(
                response=err.response,
                retry_after=err.response.headers.get("retry-after", 300),
            )
        businesses_response_data = businesses_response.json()
        if (
            not isinstance(businesses_response_data, dict)
            or "$items" not in businesses_response_data
        ):
            logger.warning(
                "Received response from Sage do not contain required field",
                extra={"response": businesses_response_data},
            )
            return businesses_response_data

        for business in businesses_response_data["$items"]:
            businesses.append(
                IntegrationBusiness(
                    platform_record_id=business["id"],
                    company_id=self.company_id,
                    name=business["displayed_as"],
                    raw=business,
                    integration=self.platform_name,
                )
            )

        logger.info(
            "Retrieved %s businesses from %s for company_id=%s",
            len(businesses),
            self.platform_name.value,
            self.company_id,
        )
        return businesses

    @execution_time_tracking(platform=IntegrationType.SAGE)
    async def get_tracking_categories(
        self, offset=0, limit=100, **kwargs
    ) -> list[IntegrationTrackingCategorySchema]:
        """
        Get tracking categories from Sage
        API docs link: https://developer.sage.com/accounting/reference/settings/#tag/Analysis-Types/operation/getAnalysisTypes
        :param offset: Offset
        :param limit: Max numbers of records to return
        :return: list of IntegrationTrackingCategorySchema objects
        """
        logger.info(
            "Retrieving tracking categories (offset=%s, limit=%s) from %s for company_id=%s",
            offset,
            limit,
            self.platform_name.value,
            self.company_id,
        )
        page = (offset // limit) + 1
        tracking_categories = []

        try:
            tracking_categories_response = await self._make_call(
                "get",
                url_path="/v3.1/analysis_types",
                params={
                    "page": page,
                    "items_per_page": limit,
                    "attributes": "all",
                },
                headers=self.headers,
            )
        except OAuthIntegrationTooManyRequestsException as err:
            raise AccountingIntegrationTooManyRequestsException(
                response=err.response,
                retry_after=err.response.headers.get("retry-after", 300),
            )

        tracking_categories_response_data = tracking_categories_response.json()
        if (
            not isinstance(tracking_categories_response_data, dict)
            or "$items" not in tracking_categories_response_data
        ):
            logger.warning(
                "Received response from Sage do not contain required field",
                extra={"response": tracking_categories_response_data},
            )
            return tracking_categories

        for tracking_category in tracking_categories_response_data["$items"]:
            tracking_category_response = await self._make_call(
                "get",
                url_path=f"/v3.1/analysis_types/{tracking_category['id']}",
                headers=self.headers,
            )
            tracking_category_response_data = tracking_category_response.json()
            options = []
            for option in tracking_category_response_data[
                "analysis_type_categories"
            ]:
                options.append(
                    IntegrationTrackingCategoryOptionSchema(
                        platform_record_id=option["id"],
                        name=option["displayed_as"],
                        raw=option,
                    )
                )
            tracking_categories.append(
                IntegrationTrackingCategorySchema(
                    platform_record_id=tracking_category["id"],
                    company_id=self.company_id,
                    name=tracking_category["displayed_as"],
                    raw=tracking_category,
                    integration=self.platform_name,
                    options=options,
                )
            )
        logger.info(
            "Retrieved %s tracking categories %s for company_id=%s",
            len(tracking_categories),
            self.platform_name.value,
            self.company_id,
        )
        return tracking_categories

    @execution_time_tracking(platform=IntegrationType.SAGE)
    async def get_accounts(
        self, offset=0, limit=100, **kwargs
    ) -> tuple[int, list[IntegrationAccount]]:
        """
        Get accounts from Sage
        API docs link: https://developer.sage.com/accounting/reference/accounting-setup/#tag/Ledger-Accounts/operation/getLedgerAccounts
        :param offset: Offset
        :param limit: Max numbers of records to return
        :param kwargs: additional params that can be passed
        :return: list of IntegrationAccount objects
        """
        logger.info(
            "Retrieving accounts (offset=%s, limit=%s) from %s for company_id=%s",
            offset,
            limit,
            self.platform_name.value,
            self.company_id,
        )
        page = (offset // limit) + 1
        accounts = []

        try:
            response = await self._make_call(
                "get",
                url_path="/v3.1/ledger_accounts",
                params={
                    "page": page,
                    "items_per_page": limit,
                    "attributes": "all",
                    "usage": "purchase",
                },
                headers=self.headers,
            )
        except OAuthIntegrationTooManyRequestsException as err:
            raise AccountingIntegrationTooManyRequestsException(
                response=err.response,
                retry_after=err.response.headers.get("retry-after", 300),
            )

        response_data = response.json()
        if (
            not isinstance(response_data, dict)
            or "$items" not in response_data
        ):
            logger.warning(
                "Received response from Sage do not contain required field",
                extra={"response": response},
            )
            return 0, accounts

        total = len(response_data["$items"])
        for account in response_data["$items"]:
            if (
                account["ledger_account_group"]["id"]
                not in self.RELEVANT_ACCOUNT_TYPES
            ):
                continue

            # Skip it as bank accounts are fetched separately for SAGE
            if account["ledger_account_type"]["id"] == "BANK":
                continue

            accounts.append(
                IntegrationAccount(
                    platform_record_id=account["id"],
                    company_id=self.company_id,
                    name=account["name"],
                    description=account["displayed_as"],
                    classification=account["ledger_account_group"]["id"],
                    type=account["ledger_account_type"]["id"],
                    code=str(account["nominal_code"]),
                    currency=None,
                    tax_code=(
                        IntegrationTaxCode(
                            platform_record_id=account["tax_rate"]["id"],
                            company_id=self.company_id,
                            name=account["tax_rate"]["displayed_as"],
                            integration=self.platform_name,
                        )
                        if account.get("tax_rate")
                        else None
                    ),
                    raw=account,
                    integration=self.platform_name,
                )
            )

        logger.info(
            "Retrieved %s accounts from %s for company_id=%s",
            len(accounts),
            self.platform_name.value,
            self.company_id,
        )

        return total, accounts

    @execution_time_tracking(platform=IntegrationType.SAGE)
    async def get_invoices(
        self, offset=0, limit=100, **kwargs
    ) -> list[IntegrationInvoice]:
        """
        Get invoices from Sage
        API docs link: https://developer.sage.com/accounting/reference/invoicing-purchases/#tag/Purchase-Invoices/operation/getPurchaseInvoices
        :param offset: Offset
        :param limit: Max numbers of records to return
        :param kwargs: additional params that can be passed
        :return: list of IntegrationInvoice objects
        """
        logger.info(
            "Retrieving invoices (offset=%s, limit=%s) from %s for company_id=%s",
            offset,
            limit,
            self.platform_name.value,
            self.company_id,
        )
        page = (offset // limit) + 1
        invoices = []

        try:
            response = await self._make_call(
                "get",
                url_path="/v3.1/purchase_invoices",
                params={
                    "page": page,
                    "items_per_page": limit,
                    "attributes": "all",
                },
                headers=self.headers,
            )
        except OAuthIntegrationTooManyRequestsException as err:
            raise AccountingIntegrationTooManyRequestsException(
                response=err.response,
                retry_after=err.response.headers.get("retry-after", 300),
            )

        response_data = response.json()
        if (
            not isinstance(response_data, dict)
            or "$items" not in response_data
        ):
            logger.warning(
                "Received response from Sage do not contain required field",
                extra={"response": response},
            )
            return invoices

        for invoice in response_data["$items"]:
            invoices.append(
                IntegrationInvoice(
                    platform_record_id=invoice["id"],
                    company_id=self.company_id,
                    line_items=[
                        IntegrationLineItem(
                            platform_record_id=li["id"],
                            company_id=self.company_id,
                            quantity=li["quantity"],
                            description="",
                            unit_price=li["unit_price"],
                            net_amount=li["net_amount"],
                            tax_amount=li["tax_amount"],
                            total_amount=li["total_amount"],
                            tax_included=li["unit_price_includes_tax"],
                            tax_codes=[li["tax_rate"]["id"]],
                            raw=li,
                            integration=self.platform_name,
                        )
                        for li in invoice["invoice_lines"]
                    ],
                    net_amount=invoice["net_amount"],
                    tax_amount=invoice["tax_amount"],
                    currency=invoice["currency"]["id"],
                    vendor=invoice["contact"]["id"],
                    total_amount=invoice["total_amount"],
                    date=invoice["date"],
                    due_date=invoice["due_date"],
                    raw=invoice,
                    integration=self.platform_name,
                )
            )

        logger.info(
            "Retrieved %s invoices (page=%s, limit=%s, offset=%s) from %s for company_id=%s",
            len(invoices),
            page,
            limit,
            offset,
            self.platform_name.value,
            self.company_id,
        )
        return invoices

    @execution_time_tracking(platform=IntegrationType.SAGE)
    async def get_tax_codes(
        self, offset=0, limit=100, **_
    ) -> list[IntegrationTaxCode]:
        """
        Get tax codes from Sage
        API docs link: https://developer.sage.com/accounting/reference/taxes/#tag/Tax-Rates/operation/getTaxRates
        :param offset: Offset
        :param limit: Max numbers of records to return
        :return: list of IntegrationTaxCode objects
        """
        logger.info(
            "Retrieving tax codes (offset=%s, limit=%s) from %s for company_id=%s",
            offset,
            limit,
            self.platform_name.value,
            self.company_id,
        )

        page = (offset // limit) + 1
        tax_codes = []
        try:
            response = await self._make_call(
                "get",
                url_path="/v3.1/tax_rates",
                params={
                    "page": page,
                    "items_per_page": limit,
                    "attributes": "all",
                    "usage": "purchase",
                },
                headers=self.headers,
            )
        except OAuthIntegrationTooManyRequestsException as err:
            raise AccountingIntegrationTooManyRequestsException(
                response=err.response,
                retry_after=err.response.headers.get("retry-after", 300),
            )
        response_data = response.json()
        if (
            not isinstance(response_data, dict)
            or "$items" not in response_data
        ):
            logger.warning(
                "Received response from Sage do not contain required field",
                extra={"response": response},
            )
            return tax_codes

        for data in response_data["$items"]:
            rate = data["percentage"]
            tax_codes.append(
                IntegrationTaxCode(
                    platform_record_id=data["id"],
                    company_id=self.company_id,
                    name=data["displayed_as"],
                    effective_rate=float(rate),
                    display_tax_rate=f"{rate}%",
                    raw=data,
                    integration=self.platform_name,
                )
            )

        logger.info(
            "Retrieved %s tax codes from %s for company_id=%s",
            len(tax_codes),
            self.platform_name.value,
            self.company_id,
        )
        return tax_codes

    @execution_time_tracking(platform=IntegrationType.SAGE)
    async def get_currencies(
        self, offset=0, limit=100, **_
    ) -> list[IntegrationCurrency]:
        """
        Get currencies from Sage
        API docs link: https://developer.sage.com/accounting/reference/currencies/#tag/Currencies/operation/getCurrencies
        :param offset: Offset
        :param limit: Max numbers of records to return
        :return: list of IntegrationCurrency objects
        """

        logger.info(
            "Fetching currencies (offset=%s, limit=%s) from %s for company_id=%s",
            offset,
            limit,
            self.platform_name.value,
            self.company_id,
        )
        page = (offset // limit) + 1
        currencies = []

        try:
            response = await self._make_call(
                "get",
                url_path="/v3.1/currencies",
                params={
                    "page": page,
                    "items_per_page": limit,
                    "attributes": "all",
                },
                headers=self.headers,
            )
        except OAuthIntegrationTooManyRequestsException as err:
            raise AccountingIntegrationTooManyRequestsException(
                response=err.response,
                retry_after=err.response.headers.get("retry-after", 300),
            )

        response_data = response.json()
        if (
            not isinstance(response_data, dict)
            or "$items" not in response_data
        ):
            logger.warning(
                "Received response from Sage do not contain required field",
                extra={"response": response},
            )
            return currencies

        for data in response_data["$items"]:
            currencies.append(
                IntegrationCurrency(
                    platform_record_id=data["id"],
                    company_id=self.company_id,
                    name=data["displayed_as"],
                    code=data["id"],
                    raw=data,
                    integration=self.platform_name,
                )
            )

        logger.info(
            "Retrieved %s currencies from %s for company_id=%s",
            len(currencies),
            self.platform_name.value,
            self.company_id,
        )

        return currencies

    @execution_time_tracking(platform=IntegrationType.SAGE)
    async def get_bank_accounts(self, offset=0, limit=100, **kwargs):
        """
        Get bank accounts from Sage
        API docs link: https://developer.sage.com/accounting/reference/banking/#tag/Bank-Accounts
        :param offset: Offset
        :param limit: Max numbers of records to return
        :param kwargs: additional params that can be passed
        :return: list of IntegrationAccount objects
        """
        logger.info(
            "Retrieving bank accounts accounts (offset=%s, limit=%s) from %s company_id=%s",
            offset,
            limit,
            self.platform_name.value,
            self.company_id,
        )
        page = (offset // limit) + 1
        bank_accounts = []

        try:
            response = await self._make_call(
                "get",
                url_path="/v3.1/bank_accounts",
                params={
                    "page": page,
                    "items_per_page": limit,
                    "attributes": "all",
                    "filter_inactive_bank_accounts": True,
                },
                headers=self.headers,
            )
        except OAuthIntegrationTooManyRequestsException as err:
            raise AccountingIntegrationTooManyRequestsException(
                response=err.response,
                retry_after=err.response.headers.get("retry-after", 300),
            )

        response_data = response.json()
        if (
            not isinstance(response_data, dict)
            or "$items" not in response_data
        ):
            logger.warning(
                "Received response from Sage do not contain required field",
                extra={"response": response},
            )
            return 0, bank_accounts

        total = len(response_data["$items"])
        for account in response_data["$items"]:
            bank_accounts.append(
                IntegrationAccount(
                    platform_record_id=account["id"],
                    company_id=self.company_id,
                    name=account["displayed_as"],
                    description=account["displayed_as"],
                    classification="ASSET",
                    type="BANK",
                    code=None,
                    currency=None,
                    tax_code=None,
                    raw=account,
                    integration=self.platform_name,
                )
            )

        logger.info(
            "Retrieved %s bank accounts from %s for company_id=%s",
            len(bank_accounts),
            self.platform_name.value,
            self.company_id,
        )

        return total, bank_accounts

    @execution_time_tracking(platform=IntegrationType.SAGE)
    async def get_vendors(
        self, offset=0, limit=100, **kwargs
    ) -> list[IntegrationVendor]:
        """
        Get vendors from Sage
        API docs link: https://developer.sage.com/accounting/reference/contacts/#tag/Contacts
        :param offset: Offset
        :param limit: Max numbers of records to return
        :return: list of IntegrationVendor objects
        """
        logger.info(
            "Retrieving vendors (offset=%s, limit=%s) from %s for company_id=%s",
            offset,
            limit,
            self.platform_name.value,
            self.company_id,
        )
        page = (offset // limit) + 1
        vendors = []

        try:
            response = await self._make_call(
                "get",
                url_path="/v3.1/contacts",
                params={
                    "page": page,
                    "items_per_page": limit,
                    "attributes": "all",
                    "contact_type_id": "VENDOR",
                },
                headers=self.headers,
            )
        except OAuthIntegrationTooManyRequestsException as err:
            raise AccountingIntegrationTooManyRequestsException(
                response=err.response,
                retry_after=err.response.headers.get("retry-after", 300),
            )
        response_data = response.json()
        if (
            not isinstance(response_data, dict)
            or "$items" not in response_data
        ):
            logger.warning(
                "Received response from Sage do not contain required field",
                extra={"response": response},
            )
            return vendors
        for data in response_data["$items"]:
            if not data.get("displayed_as"):
                logger.warning("Skip Sage vendor as Name is None - %s", data)
                continue

            vendors.append(
                IntegrationVendor(
                    platform_record_id=data["id"],
                    company_id=self.company_id,
                    name=data["displayed_as"],
                    raw=data,
                    integration=self.platform_name,
                )
            )

        logger.info(
            "Retrieved %s vendors from %s for company_id=%s",
            len(vendors),
            self.platform_name.value,
            self.company_id,
        )
        return vendors

    @execution_time_tracking(platform=IntegrationType.SAGE)
    async def _create_invoice(
        self,
        invoice_data: SageSyncInvoiceSchema,
    ) -> IntegrationInvoice:

        create_invoice_response = await self._make_call(
            "post",
            url_path="/v3.1/purchase_invoices",
            json={
                "purchase_invoice": {
                    "id": invoice_data.id,
                    "contact_id": invoice_data.contact_id,
                    "status_id": self.INVOICE_PAYMENT_STATUS_MAPPING[
                        invoice_data.status_id
                    ],
                    "date": invoice_data.date.isoformat(),
                    "due_date": invoice_data.due_date.isoformat(),
                    "invoice_lines": [
                        {
                            "description": line.description,
                            "ledger_account_id": line.ledger_account_id,
                            "quantity": line.quantity,
                            "unit_price": line.unit_price,
                            "tax_rate_id": line.tax_rate_id,
                            "tax_amount": line.tax_amount,
                        }
                        for line in invoice_data.invoice_lines
                    ],
                }
            },
            headers=self.headers,
        )
        response_data = create_invoice_response.json()
        if "contact" not in response_data:
            logger.error(
                "SAGE: Failed to create an invoice",
                extra={
                    "invoice_data": invoice_data.model_dump(),
                    "response": response_data,
                },
            )
            raise AccountingIntegrationFailedToCreateInvoiceException(
                "Failed to create invoice in Sage"
            )
        sage_invoice = IntegrationInvoice(
            platform_record_id=response_data["id"],
            company_id=self.company_id,
            date=response_data["date"],
            due_date=response_data["due_date"],
            total_amount=response_data["total_amount"],
            currency_code=response_data["currency"]["id"],
            raw=response_data,
            currency=response_data["currency"]["id"],
            net_amount=response_data["net_amount"],
            tax_amount=response_data["tax_amount"],
            line_items=[
                IntegrationLineItem(
                    platform_record_id=el["id"],
                    company_id=self.company_id,
                    unit_price=el["unit_price"],
                    total_amount=el["total_amount"],
                    tax_amount=el["tax_amount"],
                    net_amount=el["net_amount"],
                    description=el["description"],
                    quantity=el["quantity"],
                    integration=self.platform_name,
                    raw=el,
                )
                for el in response_data["invoice_lines"]
            ],
            integration=self.platform_name,
            vendor=response_data["contact"]["id"],
        )

        if invoice_data.status_id == "PAID":
            await self._create_payment(
                payment_data=SageCreatePaymentSchema(
                    document_id=sage_invoice.platform_record_id,
                    transaction_type="VENDOR_PAYMENT",
                    contact_id=invoice_data.contact_id,
                    account_id=invoice_data.payment_source,
                    amount=sage_invoice.total_amount,
                    date=invoice_data.date,
                )
            )
        return sage_invoice

    async def get_tax_rates(self):
        return []

    @execution_time_tracking(platform=IntegrationType.SAGE)
    # pylint: disable=arguments-differ
    async def add_attachment_to_document(
        self,
        file: str,
        file_name: str,
        mime_type: str,
        invoice_id: str,
        *args,
        **kwargs,
    ):

        await self._make_call(
            "post",
            url_path="/v3.1/attachments",
            json={
                "attachment": {
                    "file": file,
                    "file_name": file_name,
                    "mime_type": mime_type,
                    "attachment_context_type_id": "PURCHASE_INVOICE",
                    "attachment_context_id": invoice_id,
                }
            },
            headers=self.headers,
        )

    @execution_time_tracking(platform=IntegrationType.SAGE)
    async def create_vendor(
        self, vendor_data: CreateVendorSchema
    ) -> IntegrationVendor:

        create_response = await self._make_call(
            "post",
            url_path="/v3.1/contacts",
            json={
                "contact": {
                    "name": vendor_data.name,
                    "contact_type_ids": [SageContactTypes.VENDOR],
                }
            },
            headers=self.headers,
        )
        response_data = create_response.json()
        if "name" not in response_data:
            logger.error(
                "SAGE: Failed to create a vendor",
                extra={"vendor_info": vendor_data.model_dump()},
            )
            raise AccountingIntegrationFailedToCreateVendorException(
                "Failed to create a vendor in Sage"
            )

        return IntegrationVendor(
            platform_record_id=response_data["id"],
            company_id=self.company_id,
            name=response_data["name"],
            raw=response_data,
            integration=self.platform_name,
        )

    async def test_tenant_connection(self):
        business_id = await self._init_business_id()
        try:
            await self._make_call(
                "get",
                url_path="/v3.1/businesses/" + str(business_id),
            )
        except OAuthIntegrationBaseException as err:
            logger.error(
                "Failed to get Sage business - %s",
                err,
                extra={"company_id": self.company_id},
            )
            await self.delete_auth_from_cache()
            raise OAuthIntegrationLoginRequiredException(
                f"You are not connected to {self.platform_name.value} currently, please reconnect in order to continue your work"
            )

    async def _create_credit_note(
        self, credit_note_input_data: BaseSyncDocumentSchema
    ):
        pass

    async def _create_receipt(
        self, receipt_input_data: BaseSyncDocumentSchema
    ):
        pass

    @execution_time_tracking(platform=IntegrationType.SAGE)
    async def _create_payment(self, payment_data: SageCreatePaymentSchema):
        logger.info(
            "Creating payment for invoice",
            extra={
                "company_id": self.company_id,
                "document_platform_record_id": payment_data.document_id,
            },
        )
        response = await self._make_call(
            method="post",
            url_path="/v3.1/contact_payments",
            headers=self.headers,
            json={
                "contact_payment": {
                    "transaction_type_id": payment_data.transaction_type,
                    "contact_id": payment_data.contact_id,
                    "bank_account_id": payment_data.account_id,
                    "date": payment_data.date.isoformat(),
                    "total_amount": payment_data.amount,
                    "allocated_artefacts": [
                        {
                            "artefact_id": payment_data.document_id,
                            "amount": payment_data.amount,
                        }
                    ],
                }
            },
        )
        response_data = response.json()
        if "id" not in response_data:
            logger.error(
                "SAGE: Failed to create payment for invoice",
                extra={
                    "payment_info": payment_data.model_dump(),
                    "company_id": self.company_id,
                },
            )
            raise AccountingIntegrationFailedToCreatePaymentException(
                f"Failed to create payment for invoice: {response}",
            )

        logger.info(
            "Payment created in Sage",
            extra={
                "company_id": self.company_id,
                "document_platform_record_id": payment_data.document_id,
            },
        )

    @execution_time_tracking(platform=IntegrationType.SAGE)
    async def get_vat_registered_status(self):
        await self._init_business_id()
        logger.info(
            "Retrieving VAT registered status for Sage client",
            extra={"company_id": self.company_id, "user_id": self.user_id},
        )

        try:
            financial_settings_response = await self._make_call(
                method="get",
                url_path="/v3.1/financial_settings",
                headers=self.headers,
            )
        except OAuthIntegrationBaseException as err:
            logger.error(
                "Failed to get Sage financial settings and detect VAT registered status- %s",
                str(err),
                extra={
                    "company_id": self.company_id,
                    "user_id": self.user_id,
                    "error": str(err),
                },
            )
            return None

        tax_number = financial_settings_response.json()["tax_number"]
        is_vat_registered = bool(tax_number)
        logger.info(
            "Retrieved VAT registered status for Sage client - %s",
            is_vat_registered,
            extra={
                "company_id": self.company_id,
                "user_id": self.user_id,
                "is_vat_registered": is_vat_registered,
            },
        )
        return is_vat_registered

    async def get_organization_info(self) -> IntegrationOrganizationInfo:
        is_vat_registered = await self.get_vat_registered_status()
        return IntegrationOrganizationInfo(
            is_vat_registered=is_vat_registered,
        )
