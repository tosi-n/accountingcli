import base64
import urllib.parse
from typing import Literal

import jwt
from authlib.integrations.httpx_client import AsyncOAuth2Client
from httpx import Response

from app.core.accounting.exceptions import (
    AccountingIntegrationFailedToCreateCreditNoteException,
    AccountingIntegrationFailedToCreateInvoiceException,
    AccountingIntegrationFailedToCreatePaymentException,
    AccountingIntegrationFailedToCreateVendorException,
    AccountingIntegrationTenantMissedException,
    AccountingIntegrationTooManyRequestsException,
)
from app.core.config import settings
from app.core.loggers import logger
from app.core.services.oauth.exceptions import (
    OAuthIntegrationAPICallFailed,
    OAuthIntegrationBaseException,
    OAuthIntegrationLoginRequiredException,
    OAuthIntegrationRevokeTokenException,
    OAuthIntegrationTooManyRequestsException,
)
from app.schemas.accounting import (
    CreateVendorSchema,
    IntegrationCreditNote,
    IntegrationLineItem,
    XeroSyncSchema,
)
from app.schemas.accounting.schemas import (
    IntegrationAttachment,
    IntegrationOrganizationInfo,
    IntegrationTrackingCategoryOptionSchema,
    IntegrationTrackingCategorySchema,
    XeroCreatePaymentSchema,
)

from ...decorators import execution_time_tracking
from .base import (
    IntegrationAccount,
    IntegrationBase,
    IntegrationCurrency,
    IntegrationInvoice,
    IntegrationTaxCode,
    IntegrationType,
    IntegrationVendor,
)

XERO_REFRESH_TOKEN_EXPIRY = (
    60 * 24 * 60 * 60
)  # XERO refresh token expires after 60 days


class XeroIntegration(IntegrationBase):
    platform_name = IntegrationType.XERO

    authorization_url = str(settings.XERO_AUTHORIZATION_URL)
    scope = settings.XERO_SCOPE
    token_url = str(settings.XERO_TOKEN_URL)
    revoke_url = str(settings.XERO_REVOKE_TOKEN_URL)
    refresh_url = str(settings.XERO_TOKEN_URL)
    base_url = str(settings.XERO_BASE_URL)
    redirect_url = urllib.parse.urljoin(
        str(settings.DOMAIN), "/v2/integrations/callback/xero"
    )
    client_id = settings.XERO_CLIENT_ID
    client_secret = settings.XERO_CLIENT_SECRET

    tenant_id: int | None = None
    tenant_name: str | None = None

    PAGINATED_RESOURCES = ["invoices"]

    INVOICE_PAYMENT_STATUS_MAPPING = {
        "DRAFT": "DRAFT",
        "AWAITING_PAYMENT": "AUTHORISED",
        "PAID": "AUTHORISED",
    }

    @property
    def headers(self):
        if not self.tenant_id:
            logger.error(
                "Tenant id was not set correctly for XeroIntegrationClient"
            )
            raise AccountingIntegrationTenantMissedException

        return {"Accept": "application/json", "Xero-tenant-id": self.tenant_id}

    async def get_connected_client_id(self):
        await self._init_tenant_id()
        return self.tenant_id

    async def get_connected_client_name(self):
        await self._init_tenant_name()
        return self.tenant_name

    def _register_oauth_hooks(self, session: AsyncOAuth2Client):
        def refresh_token_headers_request_hook(
            url: str, headers: dict, body: str
        ):
            headers["Authorization"] = (
                "Basic "
                + base64.b64encode(
                    f"{self.client_id}:{self.client_secret}".encode()
                ).decode()
            )
            return url, headers, body

        session.register_compliance_hook(
            hook_type="refresh_token_request",
            hook=refresh_token_headers_request_hook,
        )

    async def _revoke_token(self):
        logger.info(
            "Trying to revoke Xero connection to tenant %s for user %s in company %s",
            self.tenant_id,
            self.user_id,
            self.company_id,
            extra={
                "user_id": self.user_id,
                "company_id": self.company_id,
                "tenant_id": self.tenant_id,
            },
        )

        try:
            connections_response = await self._make_call(
                method="get",
                url_path="/connections",
            )
        except OAuthIntegrationBaseException as err:
            logger.exception(
                "Failed to fetch active Xero connections for user - %s",
                self.user_id,
                extra={
                    "user_id": self.user_id,
                    "company_id": self.company_id,
                    "error": str(err),
                },
            )
            raise OAuthIntegrationRevokeTokenException

        connection_to_disconnect = next(
            (
                el
                for el in connections_response.json()
                if el["tenantId"] == self.tenant_id
            ),
            None,
        )
        if not connection_to_disconnect:
            logger.warning(
                "User - %s has no active Xero connection to tenant - %s in company - %s, skip revoke token",
                self.user_id,
                self.tenant_id,
                self.company_id,
                extra={
                    "company_id": self.company_id,
                    "user_id": self.user_id,
                    "tenant_id": self.tenant_id,
                },
            )
            return

        try:
            await self._make_call(
                method="delete",
                url_path=f"/connections/{connection_to_disconnect['id']}",
            )
        except OAuthIntegrationBaseException as err:
            logger.exception(
                "Failed to delete active Xero connections for user - %s",
                self.user_id,
                extra={
                    "user_id": self.user_id,
                    "company_id": self.company_id,
                    "error": str(err),
                    "tenant_id": self.tenant_id,
                },
            )
            raise OAuthIntegrationRevokeTokenException

        logger.info(
            "Disconnected Xero connection to tenant %s for user %s in company %s",
            self.tenant_id,
            self.user_id,
            self.company_id,
            extra={
                "user_id": self.user_id,
                "company_id": self.company_id,
                "tenant_id": self.tenant_id,
            },
        )

    async def add_tenant_details_to_auth(self, auth_details: dict):
        decoded = jwt.decode(
            auth_details["access_token"], options={"verify_signature": False}
        )

        connection_response = await self._make_call(
            "get",
            f"/connections?authEventId={decoded['authentication_event_id']}",
        )

        cons = connection_response.json()
        for connection in cons:
            if connection["tenantType"] == "ORGANISATION":
                auth_details["tenant_id"] = connection["tenantId"]
                auth_details["tenant_name"] = connection["tenantName"]
                logger.info(
                    "Found tenant: %s. Tenant_id: %s",
                    connection["tenantName"],
                    connection["tenantId"],
                )
                break

        auth_details["platform_user_id"] = decoded["xero_userid"]

    async def _init_tenant_id(self) -> int:
        """Read tenant ID from Xero auth details"""
        if self.tenant_id:
            return self.tenant_id

        auth_details = await self.fetch_auth_details()
        if tenant_id := auth_details.get("tenant_id"):
            self.tenant_id = tenant_id
            return tenant_id
        raise OAuthIntegrationLoginRequiredException

    async def _init_tenant_name(self) -> str:
        """Read tenant name from Xero auth details"""
        if self.tenant_name:
            return self.tenant_name

        auth_details = await self.fetch_auth_details()
        if tenant_name := auth_details.get("tenant_name"):
            self.tenant_name = tenant_name
            return tenant_name
        raise OAuthIntegrationLoginRequiredException

    @execution_time_tracking(platform=IntegrationType.XERO)
    async def get_accounts(
        self, offset=0, limit=1000, **kwargs
    ) -> tuple[int, list[IntegrationAccount]]:
        """
        Get accounts from Xero
        API docs link: https://developer.xero.com/documentation/api/accounting/accounts#get-accounts
        :param offset: Offset
        :param limit: Max numbers of records to return
        :param kwargs: additional params that can be passed
        :return: list of IntegrationAccount objects
        """
        logger.info(
            "Retrieving accounts from %s for company_id=%s, tenant_id=%s",
            self.platform_name.value,
            self.company_id,
            self.tenant_id,
        )

        accounts = []
        try:

            accounts_response = await self._make_call(
                "get",
                params={"where": 'Status=="ACTIVE"'},
                url_path="/api.xro/2.0/Accounts",
                headers=self.headers,
            )
        except OAuthIntegrationTooManyRequestsException as err:
            raise AccountingIntegrationTooManyRequestsException(
                response=err.response,
                retry_after=err.response.headers.get("retry-after", 300),
            )

        total = len(accounts_response.json().get("Accounts", []))
        for account in accounts_response.json().get("Accounts", []):
            if account["Class"] not in self.RELEVANT_ACCOUNT_TYPES:
                continue

            accounts.append(
                IntegrationAccount(
                    platform_record_id=account["AccountID"],
                    company_id=self.company_id,
                    name=account["Name"],
                    description=account.get("Description", ""),
                    classification=account["Class"],
                    type=account["Type"],
                    code=account.get("Code", ""),
                    currency=(
                        None
                        if (acc := account.get("CurrencyCode")) is None
                        else IntegrationCurrency(
                            platform_record_id=acc,
                            company_id=self.company_id,
                            code=acc,
                            integration=self.platform_name,
                        )
                    ),
                    tax_code=(
                        None
                        if (tc := account.get("TaxType")) is None
                        else IntegrationTaxCode(
                            platform_record_id=tc,
                            company_id=self.company_id,
                            name=tc,
                            integration=self.platform_name,
                        )
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

    @execution_time_tracking(platform=IntegrationType.XERO)
    async def get_currencies(
        self, *_args, **_kwargs
    ) -> list[IntegrationCurrency]:
        """
        Get currencies from Xero
        API docs link: https://developer.xero.com/documentation/api/accounting/currencies#get-currencies
        :param kwargs: additional params that can be passed
        :return: list of IntegrationCurrency objects
        """
        logger.info(
            "Retrieving currencies from %s for company_id=%s",
            self.platform_name.value,
            self.company_id,
        )

        try:
            currencies_response = await self._make_call(
                "get", "/api.xro/2.0/Currencies", headers=self.headers
            )
        except OAuthIntegrationTooManyRequestsException as err:
            raise AccountingIntegrationTooManyRequestsException(
                response=err.response,
                retry_after=err.response.headers.get("retry-after", 300),
            )

        currencies = []
        for currency in currencies_response.json().get("Currencies", []):
            currencies.append(
                IntegrationCurrency(
                    platform_record_id=currency["Code"],
                    company_id=self.company_id,
                    name=currency["Description"],
                    code=currency["Code"],
                    raw=currency,
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

    @execution_time_tracking(platform=IntegrationType.XERO)
    async def get_invoices(
        self, offset=0, limit=100, **kwargs
    ) -> list[IntegrationInvoice]:
        """
        Get invoices from Xero
        API docs link: https://developer.xero.com/documentation/api/accounting/invoices#get-invoices
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
                "/api.xro/2.0/Invoices",
                headers=self.headers,
                params={"page": page, "pageSize": limit},
            )
        except OAuthIntegrationTooManyRequestsException as err:
            raise AccountingIntegrationTooManyRequestsException(
                response=err.response,
                retry_after=err.response.headers.get("retry-after", 300),
            )
        invoices_data = response.json().get("Invoices", [])
        for invoice in invoices_data:
            try:
                attachments = await self.get_invoice_attachments(invoice)
            except OAuthIntegrationTooManyRequestsException as err:
                raise AccountingIntegrationTooManyRequestsException(
                    response=err.response,
                    retry_after=err.response.headers.get("retry-after", 300),
                )

            invoices.append(
                IntegrationInvoice(
                    platform_record_id=invoice["InvoiceID"],
                    company_id=self.company_id,
                    date=invoice["DateString"],
                    due_date=invoice.get("DueDateString"),
                    total_amount=invoice["Total"],
                    currency_code=invoice["CurrencyCode"],
                    raw=invoice,
                    currency=invoice["CurrencyCode"],
                    net_amount=invoice["SubTotal"],
                    tax_amount=invoice["TotalTax"],
                    line_items=[
                        IntegrationLineItem(
                            platform_record_id=el["LineItemID"],
                            company_id=self.company_id,
                            unit_price=el.get("UnitAmount", 0),
                            total_amount=(
                                line_amount := el.get("LineAmount", 0)
                            ),
                            tax_amount=(tax_amount := el.get("TaxAmount", 0)),
                            net_amount=line_amount - tax_amount,
                            description=el.get("Description", ""),
                            quantity=el.get("Quantity", 0),
                            integration=self.platform_name,
                            tax_included=False,
                            raw=el,
                        )
                        for el in invoice["LineItems"]
                    ],
                    integration=self.platform_name,
                    vendor=invoice["Contact"]["ContactID"],
                    attachments=attachments,
                )
            )

        logger.info(
            "Retrieved %s invoices from %s for company_id=%s",
            len(invoices),
            self.platform_name.value,
            self.company_id,
        )

        return invoices

    @execution_time_tracking(platform=IntegrationType.XERO)
    async def get_tax_codes(
        self, *_args, **_kwargs
    ) -> list[IntegrationTaxCode]:
        """
        Get tax codes from Xero
        API docs link: https://developer.xero.com/documentation/api/accounting/taxrates#get-taxrates
        :return: list of IntegrationTaxCode objects
        """

        logger.info(
            "Retrieving tax codes from %s for company_id=%s",
            self.platform_name.value,
            self.company_id,
        )

        try:
            tax_codes_response = await self._make_call(
                "get",
                "/api.xro/2.0/TaxRates",
                params={"where": 'Status=="ACTIVE"'},
                headers=self.headers,
            )
        except OAuthIntegrationTooManyRequestsException as err:
            raise AccountingIntegrationTooManyRequestsException(
                response=err.response,
                retry_after=err.response.headers.get("retry-after", 300),
            )

        tax_codes = []
        for tax_code in tax_codes_response.json().get("TaxRates", []):
            tax_codes.append(
                IntegrationTaxCode(
                    platform_record_id=tax_code["TaxType"],
                    company_id=self.company_id,
                    name=tax_code["Name"],
                    display_tax_rate=str(tax_code["DisplayTaxRate"]),
                    effective_rate=tax_code["EffectiveRate"],
                    raw=tax_code,
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

    @execution_time_tracking(platform=IntegrationType.XERO)
    async def get_tracking_categories(
        self, offset=0, limit=100, **kwargs
    ) -> list[IntegrationTrackingCategorySchema]:
        """
        Get tracking categories from Xero
        API docs link: https://developer.xero.com/documentation/api/accounting/trackingcategories#get-trackingcategories
        :param offset: Offset
        :param limit: Max numbers of records to return
        :return: list of IntegrationVendor IntegrationTrackingCategorySchema
        """

        logger.info(
            "Retrieving tracking categories from %s for company_id=%s",
            self.platform_name.value,
            self.company_id,
        )

        try:

            tracking_categories_response = await self._make_call(
                "get", "/api.xro/2.0/TrackingCategories", headers=self.headers
            )
        except OAuthIntegrationTooManyRequestsException as err:
            raise AccountingIntegrationTooManyRequestsException(
                response=err.response,
                retry_after=err.response.headers.get("retry-after", 300),
            )

        tracking_categories = []

        for category in tracking_categories_response.json().get(
            "TrackingCategories", []
        ):
            options_data = category.get("Options", [])
            options = []

            for option in options_data:
                options.append(
                    IntegrationTrackingCategoryOptionSchema(
                        platform_record_id=option["TrackingOptionID"],
                        name=option["Name"],
                        raw=option,
                    )
                )

            tracking_categories.append(
                IntegrationTrackingCategorySchema(
                    platform_record_id=category["TrackingCategoryID"],
                    company_id=self.company_id,
                    name=category["Name"],
                    raw=category,
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

    @execution_time_tracking(platform=IntegrationType.XERO)
    async def get_vendors(
        self, offset=0, limit=100, **kwargs
    ) -> list[IntegrationVendor]:
        """
        Get vendors from Xero
        API docs link: https://developer.xero.com/documentation/api/accounting/contacts#get-contacts
        :param offset: Offset
        :param limit: Max numbers of records to return
        :return: list of IntegrationVendor objects
        """

        logger.info(
            "Retrieving vendors from %s for company_id=%s",
            self.platform_name.value,
            self.company_id,
        )

        try:

            contacts_response = await self._make_call(
                "get", "/api.xro/2.0/Contacts", headers=self.headers
            )
        except OAuthIntegrationTooManyRequestsException as err:
            raise AccountingIntegrationTooManyRequestsException(
                response=err.response,
                retry_after=err.response.headers.get("retry-after", 300),
            )

        contacts = []
        for contact in contacts_response.json().get("Contacts", []):
            if contact.get("IsSupplier"):
                if not contact.get("Name"):
                    logger.warning(
                        "Skip Xero vendor as Name is None - %s", contact
                    )
                    continue
                contacts.append(
                    IntegrationVendor(
                        platform_record_id=contact["ContactID"],
                        company_id=self.company_id,
                        name=contact["Name"],
                        raw=contact,
                        integration=self.platform_name,
                    )
                )

        logger.info(
            "Retrieved %s vendors from %s for company_id=%s",
            len(contacts),
            self.platform_name.value,
            self.company_id,
        )
        return contacts

    async def _store_auth_details(
        self, auth_details: dict, expiry: int = XERO_REFRESH_TOKEN_EXPIRY
    ) -> None:
        auth_details["refresh_token_expires_in"] = expiry

        # Save or update authorization details for currently used Xero connection
        existing_integration_auth = await self.accounting_integrations_cache_manager.fetch_auth_details(  # pylint: disable=line-too-long
            platform_name=self.platform_name.value,
            user_id=self.user_id,
            company_id=self.company_id,
        )
        if existing_integration_auth:
            existing_integration_auth.update(auth_details)
            auth_details = existing_integration_auth

        self._auth_details = auth_details
        logger.info(
            "Storing Xero auth details for user_id = %s, company_id=%s",
            self.user_id,
            self.company_id,
        )

        # We should fetch connected organization details
        # and store it to a cache only once
        if "tenant_id" not in auth_details:
            await self.add_tenant_details_to_auth(auth_details)

        await self.accounting_integrations_cache_manager.store_auth_details(
            # pylint: disable=line-too-long
            platform_name=self.platform_name.value,
            user_id=self.user_id,
            company_id=self.company_id,
            auth_details=auth_details,
            expiry=auth_details["refresh_token_expires_in"],
        )

        # Get all other active Xero authorization details for user
        for (
            connection_details
        ) in await self.accounting_integrations_cache_manager.fetch_all_integration_connections_for_user(  # pylint: disable=line-too-long
            platform_name=self.platform_name.value,
            user_id=self.user_id,
        ):
            # Added it for backward compatibility (old auth details are missing platform_user_id)
            if not (
                platform_connected_user_id := self._auth_details.get(
                    "platform_user_id"
                )
            ) or platform_connected_user_id != auth_details.get(
                "platform_user_id"
            ):
                continue

            if not connection_details.get("company_id"):
                return

            # No need to update same company as it was already updated on line 643
            if connection_details.get("company_id") == str(self.company_id):
                continue

            connection_auth_details = connection_details["auth_details"]

            logger.info(
                "Updating user - %s Xero details for another company - %s that is connected using same Xero account",
                connection_details["user_id"],
                connection_details["company_id"],
                extra={
                    "updated_tenant_name": connection_auth_details.get(
                        "tenant_name"
                    ),
                },
            )

            # Set newest tokens to redis for all other companies connected
            # by same Jack and Xero user
            connection_auth_details["access_token"] = auth_details[
                "access_token"
            ]
            connection_auth_details["expires_at"] = auth_details["expires_at"]
            connection_auth_details["refresh_token"] = auth_details[
                "refresh_token"
            ]
            connection_auth_details["refresh_token_expires_in"] = auth_details[
                "refresh_token_expires_in"
            ]

            await self.accounting_integrations_cache_manager.store_auth_details(  # pylint: disable=line-too-long
                platform_name=self.platform_name.value,
                user_id=connection_details["user_id"],
                company_id=connection_details["company_id"],
                auth_details=connection_auth_details,
                expiry=auth_details["refresh_token_expires_in"],
            )

    @execution_time_tracking(platform=IntegrationType.XERO)
    async def _create_credit_note(
        self, credit_note_input_data: XeroSyncSchema
    ):
        create_credit_note_response = await self._make_call(
            "post",
            url_path="api.xro/2.0/CreditNotes",
            headers=self.headers,
            json={
                "Status": self.INVOICE_PAYMENT_STATUS_MAPPING[
                    credit_note_input_data.status
                ],
                "Contact": {"ContactID": credit_note_input_data.contact_id},
                "Date": credit_note_input_data.date.isoformat(),
                "DueDate": (
                    credit_note_input_data.due_date.isoformat()
                    if credit_note_input_data.due_date
                    else None
                ),
                "CreditNoteNumber": credit_note_input_data.invoice_id,
                "LineAmountTypes": (
                    "Exclusive"
                    if credit_note_input_data.vat_exclusive
                    else "Inclusive"
                ),
                "Type": credit_note_input_data.type.value,
                "CurrencyCode": credit_note_input_data.currency_code,
                "LineItems": [
                    {
                        "Description": line_item.description,
                        "Quantity": line_item.quantity,
                        "UnitAmount": line_item.unit_amount,
                        "AccountCode": line_item.account_code,
                        "TaxType": line_item.tax_type,
                        "Tracking": line_item.tracking,
                    }
                    for line_item in credit_note_input_data.line_items
                ],
            },
        )
        create_invoice_response_data = create_credit_note_response.json()
        if create_invoice_response_data["Status"] != "OK":
            logger.error(
                "XERO: Failed to create a credit note",
                extra={
                    "credit_note_data": credit_note_input_data.model_dump(),
                    "response": create_invoice_response_data,
                },
            )
            raise AccountingIntegrationFailedToCreateCreditNoteException(
                "Failed to create credit note in Xero"
            )

        create_credit_note_response_data = create_invoice_response_data[
            "CreditNotes"
        ][0]

        credit_note = IntegrationCreditNote(
            platform_record_id=create_credit_note_response_data[
                "CreditNoteID"
            ],
            company_id=self.company_id,
            date=create_credit_note_response_data["DateString"],
            due_date=create_credit_note_response_data.get("DueDateString"),
            total_amount=create_credit_note_response_data["Total"],
            currency_code=create_credit_note_response_data["CurrencyCode"],
            raw=create_credit_note_response_data,
            currency=create_credit_note_response_data["CurrencyCode"],
            net_amount=create_credit_note_response_data["SubTotal"],
            tax_amount=create_credit_note_response_data["TotalTax"],
            line_items=[
                IntegrationLineItem(
                    platform_record_id=el["LineItemID"],
                    company_id=self.company_id,
                    unit_price=el["UnitAmount"],
                    total_amount=el["LineAmount"],
                    tax_amount=(tax_amount := el.get("TaxAmount", 0)),
                    net_amount=el["LineAmount"] - tax_amount,
                    description=el["Description"],
                    quantity=el["Quantity"],
                    integration=self.platform_name,
                    raw=el,
                )
                for el in create_credit_note_response_data["LineItems"]
            ],
            integration=self.platform_name,
            vendor=create_credit_note_response_data["Contact"]["ContactID"],
        )

        if credit_note_input_data.status == "PAID":
            if credit_note_input_data.payment_source:
                await self._create_payment(
                    payment_data=XeroCreatePaymentSchema(
                        document_id=credit_note.platform_record_id,
                        account_id=credit_note_input_data.payment_source,
                        amount=credit_note.total_amount,
                        date=credit_note.due_date,
                    )
                )
            else:
                logger.error(
                    "Skip payment creation as payment source is not specified",
                    extra={
                        "company_id": self.company_id,
                        "document_id": credit_note.platform_record_id,
                    },
                )
                raise AccountingIntegrationFailedToCreatePaymentException(
                    "Failed to create a payment in Xero"
                )
        return credit_note

    async def _create_receipt(self, receipt_input_data: XeroSyncSchema):
        pass

    @execution_time_tracking(platform=IntegrationType.XERO)
    async def _create_invoice(
        self,
        invoice_data: XeroSyncSchema,
    ) -> IntegrationInvoice:

        create_invoice_response = await self._make_call(
            "post",
            url_path="api.xro/2.0/Invoices",
            headers=self.headers,
            json={
                "InvoiceID": invoice_data.id,
                "Status": self.INVOICE_PAYMENT_STATUS_MAPPING[
                    invoice_data.status
                ],
                "LineAmountTypes": (
                    "Exclusive" if invoice_data.vat_exclusive else "Inclusive"
                ),
                "Contact": {"ContactID": invoice_data.contact_id},
                "Date": invoice_data.date.isoformat(),
                "DueDate": (
                    invoice_data.due_date.isoformat()
                    if invoice_data.due_date
                    else None
                ),
                "InvoiceNumber": invoice_data.invoice_id,
                "Type": invoice_data.type.value,
                "CurrencyCode": invoice_data.currency_code,
                "LineItems": [
                    {
                        "Description": line_item.description,
                        "Quantity": line_item.quantity,
                        "UnitAmount": line_item.unit_amount,
                        "AccountCode": line_item.account_code,
                        "TaxType": line_item.tax_type,
                        "Tracking": line_item.tracking,
                    }
                    for line_item in invoice_data.line_items
                ],
            },
        )
        create_invoice_response_data = create_invoice_response.json()
        if create_invoice_response_data["Status"] != "OK":
            logger.error(
                "XERO: Failed to create an invoice",
                extra={
                    "invoice_data": invoice_data.model_dump(),
                    "response": create_invoice_response_data,
                },
            )
            raise AccountingIntegrationFailedToCreateInvoiceException(
                "Failed to create invoice in Xero"
            )

        created_invoice_data = create_invoice_response_data["Invoices"][0]
        created_invoice = IntegrationInvoice(
            platform_record_id=created_invoice_data["InvoiceID"],
            company_id=self.company_id,
            date=created_invoice_data["DateString"],
            due_date=created_invoice_data.get("DueDateString"),
            total_amount=created_invoice_data["Total"],
            currency_code=created_invoice_data["CurrencyCode"],
            raw=created_invoice_data,
            currency=created_invoice_data["CurrencyCode"],
            net_amount=created_invoice_data["SubTotal"],
            tax_amount=created_invoice_data["TotalTax"],
            line_items=[
                IntegrationLineItem(
                    platform_record_id=el["LineItemID"],
                    company_id=self.company_id,
                    unit_price=el["UnitAmount"],
                    total_amount=el["LineAmount"],
                    tax_amount=(tax_amount := el.get("TaxAmount", 0)),
                    net_amount=el["LineAmount"] - tax_amount,
                    description=el["Description"],
                    quantity=el["Quantity"],
                    integration=self.platform_name,
                    raw=el,
                )
                for el in created_invoice_data["LineItems"]
            ],
            integration=self.platform_name,
            vendor=created_invoice_data["Contact"]["ContactID"],
        )
        if invoice_data.status == "PAID":
            if invoice_data.payment_source:
                await self._create_payment(
                    payment_data=XeroCreatePaymentSchema(
                        document_id=created_invoice.platform_record_id,
                        account_id=invoice_data.payment_source,
                        amount=created_invoice.total_amount,
                        date=invoice_data.due_date,
                    )
                )
            else:
                logger.error(
                    "Skip payment creation as payment source is not specified",
                    extra={
                        "company_id": self.company_id,
                        "document_id": created_invoice.platform_record_id,
                    },
                )
                raise AccountingIntegrationFailedToCreatePaymentException(
                    "Cannot create a payment without Payment source specified"
                )
        return created_invoice

    async def get_tax_rates(self):
        return []

    @execution_time_tracking(platform=IntegrationType.XERO)
    async def create_vendor(
        self, vendor_data: CreateVendorSchema
    ) -> IntegrationVendor:

        request_json = {
            "Name": vendor_data.name,
        }
        if vat_number := vendor_data.vat_number:
            request_json["TaxNumber"] = vat_number
        if addresses := vendor_data.addresses:
            supplier_address = next(
                (
                    address
                    for address in addresses
                    if address.type == "Supplier Address"
                ),
                None,
            )

            if supplier_address:
                request_json["Addresses"] = [
                    {
                        "AddressType": "STREET",
                        "AddressLine1": supplier_address.first_line,
                        "City": supplier_address.city,
                        "PostalCode": supplier_address.postcode,
                    }
                ]
        create_response = await self._make_call(
            "post",
            url_path="/api.xro/2.0/Contacts",
            headers=self.headers,
            json=request_json,
        )
        create_response_data = create_response.json()
        if create_response_data["Status"] != "OK":
            logger.error(
                "XERO: Failed to create a vendor",
                extra={
                    "vendor_info": vendor_data.model_dump(),
                    "response": create_response_data,
                },
            )
            raise AccountingIntegrationFailedToCreateVendorException(
                "Failed to create a vendor in Xero"
            )

        vendor = create_response_data["Contacts"][0]
        return IntegrationVendor(
            platform_record_id=vendor["ContactID"],
            company_id=self.company_id,
            name=vendor["Name"],
            raw=vendor,
            integration=self.platform_name,
        )

    @execution_time_tracking(platform=IntegrationType.XERO)
    async def add_memo_to_invoice(
        self,
        invoice_id: str,
        memo: str,
    ):
        await self._make_call(
            "put",
            url_path=f"/api.xro/2.0/Invoices/{invoice_id}/History",
            headers=self.headers,
            json={"HistoryRecords": [{"Details": memo}]},
        )

    @execution_time_tracking(platform=IntegrationType.XERO)
    async def add_attachment_to_document(
        self,
        invoice_id: str,
        file_obj: bytes,
        filename: str,
        document_type: Literal["Invoices", "CreditNotes"],
        *args,
        **kwargs,
    ) -> None:

        await self._make_call(
            "post",
            url_path=f"/api.xro/2.0/{document_type}/{invoice_id}/Attachments/{filename}",
            headers=self.headers,
            body=file_obj,
        )

    @staticmethod
    def process_bad_request_response(response: Response):
        logger.info(
            "Processing Bad Request response - %s",
            str(response.status_code),
        )
        try:
            response_data = response.json()
        except ValueError:
            logger.warning(
                "Failed to read JSON from a response: %s", response.text
            )
            response_data = {}

        error_elements = response_data.get("Elements", [])
        error = ""
        for err in error_elements:
            error += "\n".join(
                validation_error.get("Message", "")
                for validation_error in err.get("ValidationErrors", [])
            )
        raise OAuthIntegrationAPICallFailed(
            response_data.get("Message", "") + "\n" + error
        )

    @execution_time_tracking(platform=IntegrationType.XERO)
    async def get_invoice_attachments(
        self,
        invoice_data: dict,
    ):
        if not invoice_data["HasAttachments"]:
            return []

        attachments_response = await self._make_call(
            "get",
            url_path=f"/api.xro/2.0/Invoices/{invoice_data['InvoiceID']}/Attachments",
            headers=self.headers,
        )
        attachments = []
        for attachment in attachments_response.json().get("Attachments", []):
            invoice_content = await self.get_attachment_content(
                attachment["Url"]
            )
            if not invoice_content:
                continue

            attachments.append(
                IntegrationAttachment(
                    filename=attachment["FileName"],
                    mimetype=attachment["MimeType"],
                    platform_record_id=attachment["AttachmentID"],
                    content=invoice_content,
                    raw=attachment,
                    company_id=self.company_id,
                    integration=self.platform_name,
                    s3_path=f"{self.company_id}/{self.platform_name}/{attachment['FileName']}",
                )
            )

        return attachments

    @execution_time_tracking(platform=IntegrationType.XERO)
    async def get_attachment_content(self, url: str):
        try:
            attachment_content_response = await self._make_call(
                "get",
                url_path=url,
                headers=self.headers,
            )
        except OAuthIntegrationBaseException as err:
            logger.error(
                "Failed to retrieve attachment content",
                extra={"url": url, "error": str(err)},
            )
            return None

        return attachment_content_response.content

    async def get_businesses(self, *_, **__):  # pragma: no cover
        return []

    @execution_time_tracking(platform=IntegrationType.XERO)
    async def _create_payment(self, payment_data: XeroCreatePaymentSchema):
        logger.info(
            "Creating payment for invoice",
            extra={
                "company_id": self.company_id,
                "document_id": payment_data.document_id,
            },
        )
        response = await self._make_call(
            method="put",
            url_path="/api.xro/2.0/Payments",
            headers=self.headers,
            json={
                "Invoice": {"InvoiceID": payment_data.document_id},
                "Account": {"AccountID": payment_data.account_id},
                "Date": payment_data.date.isoformat(),
                "Amount": payment_data.amount,
            },
        )
        response_data = response.json()
        if response_data["Status"] != "OK":
            logger.error(
                "Failed to create payment in Xero",
                extra={
                    "company_id": self.company_id,
                    "document_id": payment_data.document_id,
                    "response_data": response_data,
                },
            )
            raise AccountingIntegrationFailedToCreatePaymentException(
                "Failed to create payment in Xero"
            )

        logger.info(
            "Payment created in Xero",
            extra={
                "company_id": self.company_id,
                "document_id": payment_data.document_id,
            },
        )
        return response_data

    async def test_tenant_connection(self):
        try:
            connection_response = await self._make_call(
                "get",
                "/connections",
            )
        except OAuthIntegrationBaseException as err:
            logger.error(
                "Failed to get Xero connections - %s",
                err,
                extra={"company_id": self.company_id},
            )
            await self.delete_auth_from_cache()
            raise OAuthIntegrationLoginRequiredException(
                f"You are not connected to {self.platform_name.value} currently, please reconnect in order to continue your work"
            )

        cons = connection_response.json()
        auth_details = await self.fetch_auth_details()
        # check if tenant_id in auth_details is in connections list
        for connection in cons:
            if connection["tenantType"] == "ORGANISATION":
                if connection["tenantId"] == auth_details["tenant_id"]:
                    return True

        await self.delete_auth_from_cache()
        raise OAuthIntegrationLoginRequiredException(
            f"You are not connected to {self.platform_name.value} currently, please reconnect in order to continue your work"
        )

    async def get_connected_tenant_ids(self):
        try:
            connection_response = await self._make_call(
                "get",
                "/connections",
            )
        except OAuthIntegrationBaseException as err:
            logger.error(
                "Failed to get Xero connections - %s",
                err,
                extra={"company_id": self.company_id},
            )
            await self.delete_auth_from_cache()
            raise OAuthIntegrationLoginRequiredException(
                f"You are not connected to {self.platform_name.value} currently, please reconnect in order to continue your work"
            )

        return [
            el["tenantId"]
            for el in connection_response.json()
            if el["tenantType"] == "ORGANISATION"
        ]

    async def get_bank_accounts(self, *_, **__):
        return 0, []

    @execution_time_tracking(platform=IntegrationType.XERO)
    async def get_vat_registered_status(self):
        logger.info(
            "Retrieving VAT registered status for Xero client",
            extra={"company_id": self.company_id, "user_id": self.user_id},
        )

        try:
            org_info_response = await self._make_call(
                method="get",
                url_path="/api.xro/2.0/Organisation",
                headers=self.headers,
            )
        except OAuthIntegrationBaseException as err:
            logger.error(
                "Failed to get connected organization details and VAT Registered status from Xero - %s",
                str(err),
                extra={
                    "error": str(err),
                    "company_id": self.company_id,
                    "user_id": self.user_id,
                },
            )
            return None

        tenant_id = await self.get_connected_client_id()
        connected_org_info = next(
            (
                el
                for el in org_info_response.json().get("Organisations", [])
                if el["OrganisationID"] == tenant_id
            ),
            None,
        )
        if not connected_org_info:
            logger.error(
                "Could not get connected organization details from Xero organizations response",
                extra={"company_id": self.company_id, "user_id": self.user_id},
            )
            return None

        is_vat_registered = connected_org_info.get("PaysTax", None)
        logger.info(
            "Retrieved VAT registered status for Xero client - %s",
            is_vat_registered,
            extra={
                "company_id": self.company_id,
                "user_id": self.user_id,
                "is_vat_registered": is_vat_registered,
            },
        )
        return is_vat_registered

    @execution_time_tracking(platform=IntegrationType.XERO)
    async def get_organization_info(
        self,
    ) -> IntegrationOrganizationInfo | None:

        await self._init_tenant_id()
        logger.info(
            "Retrieving connected organization details from Xero",
            extra={"company_id": self.company_id, "user_id": self.user_id},
        )
        try:
            org_info_response = await self._make_call(
                method="get",
                url_path="/api.xro/2.0/Organisation",
                headers=self.headers,
            )
        except OAuthIntegrationBaseException as err:
            logger.error(
                "Failed to get connected organization details from Xero - %s",
                str(err),
                extra={
                    "error": str(err),
                    "company_id": self.company_id,
                    "user_id": self.user_id,
                },
            )
            return None

        tenant_id = await self.get_connected_client_id()
        connected_org_info = next(
            (
                el
                for el in org_info_response.json().get("Organisations", [])
                if el["OrganisationID"] == tenant_id
            ),
            None,
        )
        if not connected_org_info:
            logger.error(
                "Could not get connected organization details from Xero organizations response",
                extra={"company_id": self.company_id, "user_id": self.user_id},
            )
            return None

        is_vat_registered = connected_org_info.get("PaysTax", None)
        subscription_plan = connected_org_info.get("Class", None)
        logger.info(
            "Retrieved VAT registered status for Xero client - %s",
            is_vat_registered,
            extra={
                "company_id": self.company_id,
                "user_id": self.user_id,
                "is_vat_registered": is_vat_registered,
            },
        )
        logger.info(
            "Retrieved Organization subscription plan for Xero client - %s",
            subscription_plan,
            extra={"company_id": self.company_id, "user_id": self.user_id},
        )
        return IntegrationOrganizationInfo(
            is_vat_registered=is_vat_registered,
            subscription_plan=subscription_plan,
        )
