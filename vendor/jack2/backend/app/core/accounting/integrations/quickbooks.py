import base64
import json
import urllib.parse
import uuid
from decimal import Decimal

import httpx
from httpx import AsyncClient, codes

from app.core.accounting.constants import (
    EXTENSION_TO_CONTENT_TYPE,
    QUICKBOOKS_DUPLICATE_ERROR_CODE,
)
from app.core.accounting.exceptions import (
    AccountingIntegrationFailedToCreateCreditNoteException,
    AccountingIntegrationFailedToCreateInvoiceException,
    AccountingIntegrationFailedToCreatePaymentException,
    AccountingIntegrationFailedToCreateReceiptException,
    AccountingIntegrationTenantMissedException,
    AccountingIntegrationTooManyRequestsException,
    AccountingIntegrationVendorAlreadyExistsException,
)
from app.core.config import settings
from app.core.decorators import execution_time_tracking
from app.core.loggers import logger
from app.core.services.oauth.exceptions import (
    OAuthIntegrationBaseException,
    OAuthIntegrationLoginFailedException,
    OAuthIntegrationLoginRequiredException,
    OAuthIntegrationTooManyRequestsException,
    OAuthIntegrationValidationFailed,
)
from app.schemas.accounting import (
    CreateVendorSchema,
    IntegrationAccount,
    IntegrationAttachment,
    IntegrationCreditNote,
    IntegrationCurrency,
    IntegrationInvoice,
    IntegrationLineItem,
    IntegrationOrganizationInfo,
    IntegrationReceipt,
    IntegrationTaxCode,
    IntegrationTrackingCategoryOptionSchema,
    IntegrationTrackingCategorySchema,
    IntegrationType,
    IntegrationVendor,
    QuickbooksSyncInvoiceSchema,
    QuickBooksTaxRateSchema,
)
from app.schemas.accounting.schemas import (
    QuickBooksCreatePaymentSchema,
    QuickbooksLineItemSchema,
)

from .base import IntegrationBase


# pylint: disable=too-many-public-methods
class QuickBooksIntegration(IntegrationBase):
    platform_name = IntegrationType.QUICKBOOKS

    authorization_url = str(settings.QUICKBOOKS_AUTHORIZATION_URL)
    scope = settings.QUICKBOOKS_SCOPE
    token_url = str(settings.QUICKBOOKS_TOKEN_URL)
    revoke_url = str(settings.QUICKBOOKS_REVOKE_TOKEN_URL)
    refresh_url = str(settings.QUICKBOOKS_TOKEN_URL)
    base_url = str(settings.QUICKBOOKS_BASE_URL)
    redirect_url = urllib.parse.urljoin(
        str(settings.DOMAIN), "/v2/integrations/callback/quickbooks"
    )
    client_id = settings.QUICKBOOKS_CLIENT_ID
    client_secret = settings.QUICKBOOKS_CLIENT_SECRET
    tenant_id: str | None = None
    tenant_name: str | None = None

    @property
    def headers(self):
        """Default API call headers"""
        return {"Accept": "application/json"}

    async def sync_invoice(
        self,
        invoice_details: QuickbooksSyncInvoiceSchema,
    ):
        await self._validate_invoice_data(invoice_details)
        if invoice_details.id and invoice_details.status != "PAID":
            return await self._update_invoice(invoice_details)
        return await self._create_invoice(invoice_details)

    async def get_connected_client_id(self):
        """Read realm ID from Quickbooks token"""
        if self.tenant_id:
            return self.tenant_id

        token = await self.fetch_auth_details()
        if realm_id := token.get("realm_id"):
            self.tenant_id = realm_id
            return self.tenant_id
        raise OAuthIntegrationLoginRequiredException

    async def get_connected_client_name(self):
        """Read tenant name from Quickbooks auth details"""
        if self.tenant_name:
            return self.tenant_name

        auth_details = await self.fetch_auth_details()
        if tenant_name := auth_details.get("company_name"):
            self.tenant_name = tenant_name
            return tenant_name
        raise OAuthIntegrationLoginRequiredException

    @property
    def realm_id(self):
        if self.tenant_id:
            return self.tenant_id

        logger.error(
            "Tenant id was not set correctly for QuickbooksIntegrationClient"
        )
        raise AccountingIntegrationTenantMissedException

    async def handle_authorization_response(self, url: str) -> dict:
        """
        Validate and process authorization response from Quickbook platform.
        Exchange the authorization code for an access token and store token
        together with realm id to cache
        """
        url_bits = urllib.parse.urlparse(url)
        query_bits = urllib.parse.parse_qs(url_bits.query)

        state = self._validate_authorization_state(query_bits)

        self.company_id, self.user_id, _, self.referrer_url = (
            await self.validate_state(state)
        )

        code = self._validate_authorization_code(query_bits)
        realm_id = self.validate_realm_id(query_bits)

        # Exchange the authorization code for an access token
        session = await self._get_oauth_client(False)
        try:
            token = await session.fetch_token(
                self.token_url, client_secret=self.client_secret, code=code
            )
            token["realm_id"] = realm_id
            await self._store_auth_details(token)
        except Exception as e:
            raise OAuthIntegrationLoginFailedException(
                f"Token exchange failed {e}"
            ) from e
        return token

    @staticmethod
    def validate_realm_id(query_bits) -> str:
        """
        Validate and return realm or raise AccountingIntegrationValueError
        """
        if (
            "realmId" not in query_bits
            or len(query_bits["realmId"]) != 1
            and isinstance(query_bits["realmId"][0], str)
            or query_bits["realmId"][0] == ""
        ):
            raise OAuthIntegrationValidationFailed(
                "realmId not in correct format"
            )

        return query_bits["realmId"][0].split(",")[0]

    async def set_company_name(self):
        realm_id = await self.get_connected_client_id()
        company_info = await self._make_call(
            method="get",
            url_path=f"/v3/company/{realm_id}/companyinfo/{realm_id}",
            headers=self.headers,
        )
        company_info = company_info.json()
        company_name = company_info.get("CompanyInfo", {}).get("CompanyName")
        auth_details = await self.fetch_auth_details()
        auth_details["company_name"] = company_name
        await self._store_auth_details(auth_details)

    @execution_time_tracking(platform=IntegrationType.QUICKBOOKS)
    async def get_accounts(
        self, offset=0, limit=100, **kwargs
    ) -> tuple[int, list[IntegrationAccount]]:
        """
        Get accounts from Quickbooks
        API docs link: https://developer.intuit.com/app/developer/qbo/docs/api/accounting/all-entities/account#query-an-account
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

        accounts = []

        try:
            accounts_response = await self._make_call(
                method="get",
                url_path=f"/v3/company/{self.realm_id}/query",
                headers=self.headers,
                params={
                    "query": f"select * from Account startposition {offset} maxresults {limit}",  # nosec
                    "minorversion": 40,
                },
            )
        except OAuthIntegrationTooManyRequestsException as err:
            raise AccountingIntegrationTooManyRequestsException(
                response=err.response,
                retry_after=err.response.headers.get("retry-after", 300),
            )

        accounts_response = accounts_response.json()
        accounts_records = accounts_response.get("QueryResponse", {}).get(
            "Account", []
        )
        total = len(accounts_records)
        # Convert the API response to a list of IntegrationAccount objects
        for account in accounts_records:
            if (
                account["Classification"].upper()
                not in self.RELEVANT_ACCOUNT_TYPES
            ):
                continue

            tax_code = None
            if account.get("TaxCodeRef") is not None:
                tax_code = IntegrationTaxCode(
                    platform_record_id=account["TaxCodeRef"]["value"],
                    company_id=self.company_id,
                    name=account["TaxCodeRef"].get("name"),
                    integration=self.platform_name,
                    raw=account["TaxCodeRef"],
                )

            currency = None
            if account["CurrencyRef"] is not None:
                currency = IntegrationCurrency(
                    platform_record_id=self.get_platform_id(
                        self.realm_id, account["CurrencyRef"]["value"]
                    ),
                    company_id=self.company_id,
                    code=account["CurrencyRef"]["value"],
                    name=account["CurrencyRef"]["name"],
                    integration=self.platform_name,
                    raw=account["CurrencyRef"],
                )

            accounts.append(
                IntegrationAccount(
                    platform_record_id=self.get_platform_id(
                        self.realm_id, account["Id"]
                    ),
                    company_id=self.company_id,
                    name=account["Name"],
                    description=account.get("Description"),
                    classification=account["Classification"].upper(),
                    type=account["AccountType"].upper(),
                    code=account.get("AcctNum"),
                    currency=currency,
                    tax_code=tax_code,
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

    async def _map_tax_rates_to_tax_code_names(
        self, tax_codes: list
    ) -> list[IntegrationTaxCode]:
        matched_tax_codes = []
        tax_rate_dict = {
            tax_rate.platform_record_id: tax_rate.tax_rate
            for tax_rate in await self.get_tax_rates()
        }

        for tax_code_data in tax_codes:
            if tax_code_data.get("Active", True):
                for detail in tax_code_data.get("PurchaseTaxRateList", {}).get(
                    "TaxRateDetail", []
                ):
                    ref = detail.get("TaxRateRef", {})
                    if (
                        tax_rate_value := tax_rate_dict.get(ref.get("value"))
                    ) is not None:
                        matched_tax_codes.append(
                            IntegrationTaxCode(
                                platform_record_id=tax_code_data["Id"],
                                company_id=self.company_id,
                                name=tax_code_data["Name"],
                                display_tax_rate=str(tax_rate_value),
                                effective_rate=tax_rate_value,
                                raw=tax_code_data,
                                integration=self.platform_name,
                            )
                        )
                        break

        return matched_tax_codes

    # pylint: disable=line-too-long
    async def get_tax_rates(self) -> list[QuickBooksTaxRateSchema]:
        """
        Get Tax rates from Quickbooks
        API docs link: https://developer.intuit.com/app/developer/qbo/docs/api/accounting/all-entities/taxrate
        :return: list of QuickBooksTaxRateSchema objects
        """
        logger.info(
            "Retrieving tax rates from %s for company_id=%s",
            self.platform_name.value,
            self.company_id,
        )
        try:
            tax_codes_response = await self._make_call(
                method="get",
                url_path=f"/v3/company/{self.realm_id}/query",
                headers=self.headers,
                params={
                    "query": "select * from TaxRate",  # nosec
                },
            )
        except OAuthIntegrationTooManyRequestsException as err:
            raise AccountingIntegrationTooManyRequestsException(
                response=err.response,
                retry_after=err.response.headers.get("retry-after", 300),
            )

        tax_rates_response = tax_codes_response.json()
        return [
            QuickBooksTaxRateSchema(
                platform_record_id=tax_rate["Id"],
                tax_rate=float(tax_rate["RateValue"]),
            )
            for tax_rate in tax_rates_response.get("QueryResponse", {}).get(
                "TaxRate", []
            )
        ]

    @execution_time_tracking(platform=IntegrationType.QUICKBOOKS)
    async def get_tax_codes(
        self, offset: int = 0, limit: int = 100, **_
    ) -> list[IntegrationTaxCode]:
        """
        Get Tax codes from Quickbooks
        API docs link: https://developer.intuit.com/app/developer/qbo/docs/api/accounting/all-entities/taxcode#query-a-taxcode
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
        try:
            tax_codes_response = await self._make_call(
                method="get",
                url_path=f"/v3/company/{self.realm_id}/query",
                headers=self.headers,
                params={
                    "query": f"select * from TaxCode startposition {offset} maxresults {limit}",  # nosec
                },
            )
        except OAuthIntegrationTooManyRequestsException as err:
            raise AccountingIntegrationTooManyRequestsException(
                response=err.response,
                retry_after=err.response.headers.get("retry-after", 300),
            )

        tax_codes_response = tax_codes_response.json()
        tax_codes = tax_codes_response.get("QueryResponse", {}).get(
            "TaxCode", []
        )

        logger.info(
            "Retrieved %s tax codes from %s for company_id=%s",
            len(tax_codes),
            self.platform_name.value,
            self.company_id,
        )

        return await self._map_tax_rates_to_tax_code_names(tax_codes)

    @execution_time_tracking(platform=IntegrationType.QUICKBOOKS)
    async def get_tracking_categories(
        self, offset=0, limit=100, **kwargs
    ) -> list[IntegrationTrackingCategorySchema]:
        """
        Get Tracking categories from Quickbooks
        API docs link: https://developer.intuit.com/app/developer/qbo/docs/api/accounting/all-entities/class#query-a-class
        :param offset: Offset
        :param limit: Max numbers of records to return
        :return: list of IntegrationTaxCode objects
        """

        logger.info(
            "Retrieving tracking categories (offset=%s, limit=%s) from %s for company_id=%s",
            offset,
            limit,
            self.platform_name.value,
            self.company_id,
        )

        try:
            tracking_categories_response = await self._make_call(
                method="get",
                url_path=f"/v3/company/{self.realm_id}/query",
                headers=self.headers,
                params={
                    "query": (
                        f"SELECT * "
                        f"FROM Class "
                        f"ORDER BY Metadata.CreateTime DESC "
                        f"STARTPOSITION {offset} "  # nosec
                        f"MAXRESULTS {limit}"  # nosec
                    ),
                },
            )
        except OAuthIntegrationTooManyRequestsException as err:
            raise AccountingIntegrationTooManyRequestsException(
                response=err.response,
                retry_after=err.response.headers.get("retry-after", 300),
            )

        tracking_categories_response_data = tracking_categories_response.json()
        tracking_categories_data = tracking_categories_response_data.get(
            "QueryResponse", {}
        ).get("Class", [])

        tracking_categories_options = []
        for tracking_category in tracking_categories_data:
            tracking_categories_options.append(
                IntegrationTrackingCategoryOptionSchema(
                    platform_record_id=tracking_category["Id"],
                    name=tracking_category["FullyQualifiedName"],
                    parent_ref=tracking_category.get("ParentRef", {}).get(
                        "value"
                    ),
                )
            )
        # Quickbooks has only tracking category options so we create a default tracking category
        tracking_category = IntegrationTrackingCategorySchema(
            company_id=self.company_id,
            name="Default",
            integration=self.platform_name,
            options=tracking_categories_options,
            platform_record_id="N/A",  # add N/a to enforce uniqueness
        )

        logger.info(
            "Retrieved %s tracking categories options %s for company_id=%s",
            len(tracking_categories_options),
            self.platform_name.value,
            self.company_id,
        )

        return [tracking_category]

    @execution_time_tracking(platform=IntegrationType.QUICKBOOKS)
    async def get_vendors(
        self, offset=0, limit=100, **kwargs
    ) -> list[IntegrationVendor]:
        """
        Get Vendors from Quickbooks
        API docs link: https://developer.intuit.com/app/developer/qbo/docs/api/accounting/all-entities/vendor#query-a-vendor
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

        vendors = []
        try:
            vendors_response = await self._make_call(
                method="get",
                url_path=f"/v3/company/{self.realm_id}/query",
                headers=self.headers,
                params={
                    "query": f"select * from vendor startposition {offset} maxresults {limit}",  # nosec
                },
            )
        except OAuthIntegrationTooManyRequestsException as err:
            raise AccountingIntegrationTooManyRequestsException(
                response=err.response,
                retry_after=err.response.headers.get("retry-after", 300),
            )

        vendors_response = vendors_response.json()
        vendors_records = vendors_response.get("QueryResponse", {}).get(
            "Vendor", []
        )

        # Convert the API response to a list of IntegrationVendor objects
        for vendor in vendors_records:
            if not vendor.get("DisplayName"):
                logger.warning(
                    "Skip Quickbooks vendor as Name is None - %s", vendor
                )
                continue

            vendors.append(
                IntegrationVendor(
                    platform_record_id=self.get_platform_id(
                        self.realm_id, vendor["Id"]
                    ),
                    company_id=self.company_id,
                    name=vendor["DisplayName"],
                    raw=vendor,
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

    @execution_time_tracking(platform=IntegrationType.QUICKBOOKS)
    async def get_invoices(
        self, offset=0, limit=100, **kwargs
    ) -> list[IntegrationInvoice]:
        """
        Get Invoices from Quickbooks
        API docs link: https://developer.intuit.com/app/developer/qbo/docs/api/accounting/all-entities/invoice#query-an-invoice
        :param offset: Offset
        :param limit: Max numbers of records to return
        :return: list of IntegrationInvoice objects
        """
        logger.info(
            "Retrieving invoices (offset=%s, limit=%s) from %s for company_id=%s",
            offset,
            limit,
            self.platform_name.value,
            self.company_id,
        )
        invoices = []
        try:
            invoices_response = await self._make_call(
                method="get",
                url_path=f"/v3/company/{self.realm_id}/query",
                headers=self.headers,
                params={
                    "query": f"select * from Invoice startposition {offset} maxresults {limit}",  # nosec
                },
            )
        except OAuthIntegrationTooManyRequestsException as err:
            raise AccountingIntegrationTooManyRequestsException(
                response=err.response,
                retry_after=err.response.headers.get("retry-after", 300),
            )

        invoices_response = invoices_response.json()

        invoices_records = invoices_response.get("QueryResponse", {}).get(
            "Invoice", []
        )

        # Convert the API response to a list of Integrationinvoice objects
        for invoice in invoices_records:
            currency = None
            if currency_ref := invoice.get("CurrencyRef"):
                currency = currency_ref["value"]
            vendor = None
            if vendor_ref := invoice.get("CustomerRef"):
                vendor = self.get_platform_id(
                    self.realm_id, vendor_ref["value"]
                )

            try:
                attachments = await self.get_invoice_attachments(invoice)
            except OAuthIntegrationTooManyRequestsException as err:
                raise AccountingIntegrationTooManyRequestsException(
                    response=err.response,
                    retry_after=err.response.headers.get("retry-after", 300),
                )

            invoices.append(
                IntegrationInvoice(
                    platform_record_id=self.get_platform_id(
                        self.realm_id, invoice["Id"]
                    ),
                    company_id=self.company_id,
                    due_date=invoice["DueDate"],
                    date=invoice["TxnDate"],
                    total_amount=invoice["TotalAmt"],
                    tax_amount=0,
                    net_amount=invoice["TotalAmt"],
                    vendor=vendor,
                    currency=currency,
                    line_items=[
                        IntegrationLineItem(
                            platform_record_id=self.get_platform_id(
                                self.realm_id, li.get("Id")
                            ),
                            company_id=self.company_id,
                            unit_price=0,
                            quantity=1,
                            net_amount=0,
                            total_amount=li["Amount"],
                            tax_codes=[],
                            tax_included=False,
                            raw=li,
                            integration=self.platform_name,
                        )
                        for li in invoice.get("Line", [])
                        if "Id" in li
                    ],
                    raw=invoice,
                    integration=self.platform_name,
                    attachments=attachments,
                )
            )

        logger.info(
            "Retrieved %s invoices (offset=%s, limit=%s) from %s for company_id=%s",
            len(invoices),
            offset,
            limit,
            self.platform_name.value,
            self.company_id,
        )
        return invoices

    def get_platform_id(self, realm_id: str | int, id_: str) -> str:
        return realm_id + "_" + id_

    async def _store_auth_details(
        self, auth_details: dict, expiry=3600
    ) -> None:
        expiry = auth_details["x_refresh_token_expires_in"]
        auth_details["refresh_token_expires_in"] = expiry
        await super()._store_auth_details(auth_details, expiry)

    @execution_time_tracking(platform=IntegrationType.QUICKBOOKS)
    async def get_exchange_rate(
        self, currency_code: str, as_of_date: str = None
    ) -> float | None:
        """
        Get exchange rate from Quickbooks
        API docs link:
        https://developer.intuit.com/app/developer/qbo/docs/api/accounting/all-entities/exchangerate
        :param currency_code: Currency to convert from
        :param as_of_date: Date to get exchange rate for
        :return: Exchange rate
        """
        logger.info(
            "Fetching exchange rate from %s for company_id=%s. Currency code - %s",
            self.platform_name.value,
            self.company_id,
            currency_code,
        )

        exchange_rate = None
        try:
            exchange_rate_response = await self._make_call(
                method="get",
                url_path=f"/v3/company/{self.realm_id}/exchangerate",
                headers=self.headers,
                params={
                    "sourcecurrencycode": currency_code,
                    "asofdate": as_of_date,
                },
            )
        except OAuthIntegrationTooManyRequestsException as err:
            raise AccountingIntegrationTooManyRequestsException(
                response=err.response,
                retry_after=err.response.headers.get("retry-after", 300),
            )

        exchange_rate_response = exchange_rate_response.json()
        exchange_rate = exchange_rate_response.get("ExchangeRate", {}).get(
            "Rate", None
        )
        return exchange_rate

    async def get_invoice_sync_token(self, invoice_id: str) -> str:
        invoice_data = await self._make_call(
            method="get",
            url_path=f"/v3/company/{self.realm_id}/bill/{invoice_id}",
            headers=self.headers,
        )

        synchronization_token = (
            invoice_data.json().get("Bill", {}).get("SyncToken")
        )
        if synchronization_token is None:
            raise AccountingIntegrationFailedToCreateInvoiceException(
                "Synchronization token is not present for the selected invoice"
            )
        return synchronization_token

    @staticmethod
    def calculate_transaction_amount(
        vat_exclusive: bool, line_item: QuickbooksLineItemSchema
    ) -> str:
        total_amount = Decimal(str(line_item.unit_amount)) * Decimal(
            str(line_item.quantity)
        )
        if vat_exclusive:
            return str(total_amount)
        return str(total_amount - Decimal(str(line_item.tax_amount)))

    @execution_time_tracking(platform=IntegrationType.QUICKBOOKS)
    async def _update_invoice(self, invoice_data: QuickbooksSyncInvoiceSchema):
        update_invoice_response = await self._make_call(
            method="post",
            url_path=f"/v3/company/{self.realm_id}/bill",
            headers=self.headers,
            json={
                "Id": invoice_data.id,
                "SyncToken": await self.get_invoice_sync_token(
                    invoice_data.id
                ),
                "Line": [
                    {
                        "DetailType": "AccountBasedExpenseLineDetail",
                        "Amount": self.calculate_transaction_amount(
                            invoice_data.vat_exclusive, line
                        ),
                        "Description": line.description,
                        "AccountBasedExpenseLineDetail": {
                            "AccountRef": {"value": line.account_category},
                            "TaxCodeRef": {"value": line.tax_code},
                        },
                    }
                    for line in invoice_data.line_items
                ],
                "DocNumber": invoice_data.invoice_id,
                "VendorRef": {"value": invoice_data.vendor_id},
                "TxnDate": invoice_data.date.isoformat(),
                "DueDate": (
                    invoice_data.date_payment_due.isoformat()
                    if invoice_data.date_payment_due
                    else None
                ),
                "CurrencyRef": {"value": invoice_data.currency},
                "ExchangeRate": invoice_data.exchange_rate,
                "PrivateNote": invoice_data.memo,
                "GlobalTaxCalculation": (
                    "TaxExcluded"
                    if invoice_data.vat_exclusive
                    else "TaxInclusive"
                ),
            },
        )

        update_invoice_response = update_invoice_response.json()
        invoice = update_invoice_response.get("Bill", {})
        vendor = None
        if vendor_ref := invoice.get("VendorRef"):
            vendor = self.get_platform_id(self.realm_id, vendor_ref["value"])

        return IntegrationInvoice(
            platform_record_id=self.get_platform_id(
                self.realm_id, invoice["Id"]
            ),
            company_id=self.company_id,
            due_date=invoice["DueDate"],
            date=invoice["TxnDate"],
            total_amount=invoice["TotalAmt"],
            tax_amount=0,
            net_amount=invoice["TotalAmt"],
            vendor=vendor,
            currency=invoice.get("CurrencyRef", {}).get("value", None),
            line_items=[
                IntegrationLineItem(
                    platform_record_id=self.get_platform_id(
                        self.realm_id, li.get("Id")
                    ),
                    company_id=self.company_id,
                    unit_price=0,
                    quantity=1,
                    net_amount=0,
                    total_amount=li["Amount"],
                    tax_codes=[],
                    raw=li,
                    integration=self.platform_name,
                )
                for li in invoice.get("Line", [])
                if "Id" in li
            ],
            raw=invoice,
            integration=self.platform_name,
        )

    @execution_time_tracking(platform=IntegrationType.QUICKBOOKS)
    async def _create_invoice(
        self, invoice_data: QuickbooksSyncInvoiceSchema
    ) -> IntegrationInvoice:
        create_invoice_response = await self._make_call(
            method="post",
            url_path=f"/v3/company/{self.realm_id}/bill",
            headers=self.headers,
            json={
                "Line": [
                    {
                        "DetailType": "AccountBasedExpenseLineDetail",
                        "Amount": self.calculate_transaction_amount(
                            invoice_data.vat_exclusive, line
                        ),
                        "Id": invoice_data.id,
                        "Description": line.description,
                        "AccountBasedExpenseLineDetail": {
                            "AccountRef": {"value": line.account_category},
                            "TaxCodeRef": {"value": line.tax_code},
                        },
                    }
                    for line in invoice_data.line_items
                ],
                "DocNumber": invoice_data.invoice_id,
                "VendorRef": {"value": invoice_data.vendor_id},
                "TxnDate": invoice_data.date.isoformat(),
                "DueDate": (
                    invoice_data.date_payment_due.isoformat()
                    if invoice_data.date_payment_due
                    else None
                ),
                "CurrencyRef": {"value": invoice_data.currency},
                "ExchangeRate": invoice_data.exchange_rate,
                "PrivateNote": invoice_data.memo,
                "GlobalTaxCalculation": (
                    "TaxExcluded"
                    if invoice_data.vat_exclusive
                    else "TaxInclusive"
                ),
            },
        )
        create_invoice_response = create_invoice_response.json()
        invoice = create_invoice_response.get("Bill", {})
        vendor = None
        if vendor_ref := invoice.get("VendorRef"):
            vendor = self.get_platform_id(self.realm_id, vendor_ref["value"])

        invoice_created = IntegrationInvoice(
            platform_record_id=self.get_platform_id(
                self.realm_id, invoice["Id"]
            ),
            company_id=self.company_id,
            due_date=invoice["DueDate"],
            date=invoice["TxnDate"],
            total_amount=invoice["TotalAmt"],
            tax_amount=0,
            net_amount=invoice["TotalAmt"],
            vendor=vendor,
            currency=invoice.get("CurrencyRef", {}).get("value", None),
            line_items=[
                IntegrationLineItem(
                    platform_record_id=self.get_platform_id(
                        self.realm_id, li.get("Id")
                    ),
                    company_id=self.company_id,
                    unit_price=0,
                    quantity=1,
                    net_amount=0,
                    total_amount=li["Amount"],
                    tax_codes=[],
                    raw=li,
                    integration=self.platform_name,
                )
                for li in invoice.get("Line", [])
                if "Id" in li
            ],
            raw=invoice,
            integration=self.platform_name,
        )

        if invoice_data.status == "PAID":
            await self._create_payment(
                payment_data=QuickBooksCreatePaymentSchema(
                    amount=invoice_created.total_amount,
                    payment_source=invoice_data.payment_source,
                    payment_type=invoice_data.payment_source_type,
                    customer_id=invoice_data.vendor_id,
                    transaction_platform_id=(
                        invoice_created.platform_record_id.split("_")[-1]
                    ),
                    transaction_type="Bill",
                )
            )

        return invoice_created

    @execution_time_tracking(platform=IntegrationType.QUICKBOOKS)
    async def get_currencies(
        self, *_args, **_kwargs
    ) -> list[IntegrationCurrency]:
        """
        Get currencies from Quickbooks
        API docs link: https://developer.intuit.com/app/developer/qbo/docs/workflows/manage-multiple-currencies#retrieving-the-active-currency-list
        :return: list of IntegrationCurrency objects
        """
        logger.info(
            "Retrieving currencies from %s for company_id=%s",
            self.platform_name.value,
            self.company_id,
        )

        currencies = []
        try:
            currencies_response = await self._make_call(
                method="get",
                url_path=f"/v3/company/{self.realm_id}/query",
                headers=self.headers,
                params={
                    "query": "select * from currency",
                },
            )
        except OAuthIntegrationTooManyRequestsException as err:
            raise AccountingIntegrationTooManyRequestsException(
                response=err.response,
                retry_after=err.response.headers.get("retry-after", 300),
            )

        currencies_response = currencies_response.json()
        currencies_records = currencies_response.get("QueryResponse", {}).get(
            "CompanyCurrency", []
        )

        for currency in currencies_records:
            currencies.append(
                IntegrationCurrency(
                    platform_record_id=self.get_platform_id(
                        self.realm_id, currency["Id"]
                    ),
                    company_id=self.company_id,
                    code=currency["Code"],
                    name=currency["Name"],
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

    @execution_time_tracking(platform=IntegrationType.QUICKBOOKS)
    async def add_attachment_to_document(
        self,
        invoice_id: str,
        file_obj: bytes,
        filename: str,
        document_type: str,
        *args,
        **kwargs,
    ) -> None:
        boundary = uuid.uuid4()

        metadata = {
            "FileName": filename,
            "AttachableRef": [
                {
                    "EntityRef": {
                        "type": document_type,
                        "value": invoice_id.split("_")[-1],
                    }
                }
            ],
        }

        encoded_file_content = base64.b64encode(file_obj).decode()
        file_type = filename.split(".")[-1].strip().lower()
        content_type = EXTENSION_TO_CONTENT_TYPE.get(
            file_type, "application/pdf"
        )

        request_body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file_metadata_01"\r\n'
            f"Content-Type: application/json; charset=UTF-8\r\n"
            f'Content-Transfer-Encoding: 8bit"\r\n\r\n'
            f"{json.dumps(metadata)}\r\n"
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file_content_01"; filename="{filename}"\r\n'
            f"Content-Type: {content_type}\r\n"
            f"Content-Transfer-Encoding: base64\r\n\r\n"
            f"{encoded_file_content}\r\n"
            f"--{boundary}--\r\n"
        )

        request_body = str(request_body)
        await self._make_call(
            "post",
            url_path=f"/v3/company/{self.realm_id}/upload",
            headers={
                "Content-Type": f"multipart/form-data; boundary={boundary}",
                "Accept": "application/json",
            },
            body=request_body,
        )

    @execution_time_tracking(platform=IntegrationType.QUICKBOOKS)
    async def create_vendor(
        self, vendor_data: CreateVendorSchema
    ) -> IntegrationVendor:
        request_json = {"DisplayName": vendor_data.name}

        if currency := vendor_data.currency:
            request_json["CurrencyRef"] = {"value": currency}

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
                request_json["BillAddr"] = {
                    "Line1": supplier_address.first_line,
                    "Line2": supplier_address.second_line,
                    "City": supplier_address.city,
                    "PostalCode": supplier_address.postcode,
                    "Country": supplier_address.country,
                }
        try:
            create_vendor_response = await self._make_call(
                method="post",
                url_path=f"/v3/company/{self.realm_id}/vendor",
                headers=self.headers,
                json=request_json,
            )
            create_vendor_response = create_vendor_response.json()
            vendor = create_vendor_response.get("Vendor", {})
            return IntegrationVendor(
                platform_record_id=self.get_platform_id(
                    self.realm_id, vendor["Id"]
                ),
                company_id=self.company_id,
                name=vendor["DisplayName"],
                raw=vendor,
                integration=self.platform_name,
            )
        except OAuthIntegrationBaseException as err:
            error_data = json.loads(str(err))
            if (
                error_data.get("Fault", {}).get("Error", [{}])[0].get("code")
                == QUICKBOOKS_DUPLICATE_ERROR_CODE  # QuickBooks error code for duplicate name already exists
            ):
                raise AccountingIntegrationVendorAlreadyExistsException(
                    "Vendor already exists in QuickBooks"
                )
            raise err

    @execution_time_tracking(platform=IntegrationType.QUICKBOOKS)
    async def get_vendor_by_name(self, name: str):
        try:
            logger.info(
                "Getting vendor by name from Quickbooks",
                extra={
                    "company_id": self.company_id,
                    "vendor_name": name,
                },
            )
            vendor_response = await self._make_call(
                method="get",
                url_path=f"/v3/company/{self.realm_id}/query",
                headers=self.headers,
                params={
                    "query": f"select * from vendor where DisplayName = '{name}'",  # nosec
                },
            )
            vendor_response_data = vendor_response.json()
            vendor_records = vendor_response_data.get("QueryResponse", {}).get(
                "Vendor", []
            )
            if not vendor_records:
                raise OAuthIntegrationValidationFailed("Vendor not found")
            vendor = vendor_records[0]
            return IntegrationVendor(
                platform_record_id=self.get_platform_id(
                    self.realm_id, vendor["Id"]
                ),
                company_id=self.company_id,
                name=vendor["DisplayName"],
                raw=vendor,
                integration=self.platform_name,
            )
        except OAuthIntegrationBaseException as err:
            logger.error(
                "Failed to get vendor by name in Quickbooks - %s",
                err,
                extra={
                    "company_id": self.company_id,
                    "vendor_name": name,
                },
            )
            raise err

    @execution_time_tracking(platform=IntegrationType.QUICKBOOKS)
    async def get_invoice_attachments(self, invoice):
        attachments = []
        get_attachments_response = await self._make_call(
            method="post",
            url_path=f"/v3/company/{self.realm_id}/query",
            headers=self.headers,
            params={
                "query": f"select * from attachable where AttachableRef.EntityRef.Type = 'Bill' and AttachableRef.EntityRef.value = '{invoice['Id']}'",  # nosec
            },
        )
        for attachment in (
            get_attachments_response.json()
            .get("QueryResponse", {})
            .get("Attachable", [])
        ):
            download_response = await self.download_attachment(
                attachment["TempDownloadUri"]
            )
            if not download_response:
                continue
            attachments.append(
                IntegrationAttachment(
                    filename=attachment["FileName"],
                    mimetype=attachment["ContentType"],
                    platform_record_id=self.get_platform_id(
                        self.realm_id, attachment["Id"]
                    ),
                    content=download_response.content,
                    raw=attachment,
                    company_id=self.company_id,
                    integration=self.platform_name,
                    s3_path=f"/{self.company_id}/{self.platform_name}/{attachment['FileName']}",
                )
            )
        return attachments

    @staticmethod
    async def download_attachment(download_url: str):
        async with AsyncClient() as client:
            try:
                file_response = await client.get(download_url)
                return file_response
            except httpx.HTTPError:
                return None

    async def get_businesses(self, *_, **__):  # pragma: no cover
        return []

    async def test_tenant_connection(self):
        client_id = await self.get_connected_client_id()
        try:
            await self._make_call(
                method="get",
                url_path=f"/v3/company/{client_id}/companyinfo/{client_id}",
                headers=self.headers,
            )
        except OAuthIntegrationBaseException as err:
            logger.error(
                "Failed to get Quickbooks company info - %s",
                err,
                extra={"company_id": self.company_id},
            )
            await self.delete_auth_from_cache()
            raise OAuthIntegrationLoginRequiredException(
                f"You are not connected to {self.platform_name.value} currently, please reconnect in order to continue your work"
            )

    @execution_time_tracking(platform=IntegrationType.QUICKBOOKS)
    async def _create_payment(
        self, payment_data: QuickBooksCreatePaymentSchema
    ):
        logger.info(
            "Creating payment for invoice",
            extra={
                "company_id": self.company_id,
                "customer_id": payment_data.customer_id,
            },
        )
        response = await self._make_call(
            method="post",
            url_path=f"/v3/company/{self.realm_id}/billpayment",
            headers=self.headers,
            json={
                "VendorRef": {"value": payment_data.customer_id},
                "TotalAmt": payment_data.amount,
                "PayType": payment_data.payment_type,
                "Line": [
                    {
                        "Amount": payment_data.amount,
                        "LinkedTxn": [
                            {
                                "TxnId": payment_data.transaction_platform_id,
                                "TxnType": payment_data.transaction_type,
                            }
                        ],
                    }
                ],
                "CheckPayment": {
                    "BankAccountRef": {"value": payment_data.payment_source}
                },
            },
        )

        response_data = response.json()
        if response.status_code != codes.OK:
            logger.error(
                "Failed to create payment in Quickbooks",
                extra={
                    "company_id": self.company_id,
                    "customer_id": payment_data.customer_id,
                    "response_data": response_data,
                },
            )

            raise AccountingIntegrationFailedToCreatePaymentException(
                "Failed create payment in QuickBooks"
            )

        logger.info(
            "Payment created in Quickbooks",
            extra={
                "company_id": self.company_id,
                "customer_id": payment_data.customer_id,
            },
        )
        return response_data

    @execution_time_tracking(platform=IntegrationType.QUICKBOOKS)
    async def _create_credit_note(
        self, credit_note_input_data: QuickbooksSyncInvoiceSchema
    ):
        create_credit_note_response = await self._make_call(
            method="post",
            url_path=f"/v3/company/{self.realm_id}/vendorcredit",
            headers=self.headers,
            json={
                "VendorRef": {"value": credit_note_input_data.vendor_id},
                "Line": [
                    {
                        "Amount": self.calculate_transaction_amount(
                            credit_note_input_data.vat_exclusive, line
                        ),
                        "DetailType": "AccountBasedExpenseLineDetail",
                        "AccountBasedExpenseLineDetail": {
                            "AccountRef": {"value": line.account_category},
                            "TaxCodeRef": {"value": line.tax_code},
                        },
                        "Description": line.description,
                    }
                    for line in credit_note_input_data.line_items
                ],
                "DocNumber": credit_note_input_data.invoice_id,
                "TxnDate": credit_note_input_data.date_payment_due.isoformat(),
                "PrivateNote": credit_note_input_data.memo,
                "GlobalTaxCalculation": (
                    "TaxExcluded"
                    if credit_note_input_data.vat_exclusive
                    else "TaxInclusive"
                ),
            },
        )
        if create_credit_note_response.status_code != codes.OK:
            logger.error(
                "QuickBooks: Failed to create a credit note",
                extra={
                    "credit_note_data": credit_note_input_data.model_dump(),
                    "response": create_credit_note_response,
                },
            )
            raise AccountingIntegrationFailedToCreateCreditNoteException(
                "Failed to create credit note in QuickBooks"
            )

        create_credit_note_response_data = (
            create_credit_note_response.json().get("VendorCredit", {})
        )
        return IntegrationCreditNote(
            platform_record_id=create_credit_note_response_data["Id"],
            company_id=self.company_id,
            date=create_credit_note_response_data["TxnDate"],
            total_amount=(
                total_amount := create_credit_note_response_data["TotalAmt"]
            ),
            tax_amount=(
                tax_amount := create_credit_note_response_data.get(
                    "TxnTaxDetail", {}
                ).get("TotalTax", 0)
            ),
            net_amount=(total_amount - tax_amount),
            currency_code=create_credit_note_response_data.get(
                "CurrencyRef", {}
            ).get("value"),
            raw=create_credit_note_response_data,
            currency=create_credit_note_response_data.get(
                "CurrencyRef", {}
            ).get("name"),
            line_items=[
                IntegrationLineItem(
                    platform_record_id=line.get("Id"),
                    company_id=self.company_id,
                    total_amount=(total_amount := line.get("Amount", 0)),
                    net_amount=(total_amount - tax_amount),
                    unit_price=line.get("SalesItemLineDetail", {}).get(
                        "UnitPrice"
                    ),
                    quantity=line.get("SalesItemLineDetail", {}).get("Qty"),
                    description=line.get("Description"),
                    integration=self.platform_name,
                    raw=line,
                )
                for line in create_credit_note_response_data.get("Line", [])
                if line.get("DetailType") == "SalesItemLineDetail"
            ],
            integration=self.platform_name,
            vendor=create_credit_note_response_data.get("CustomerRef", {}).get(
                "name"
            ),
        )

    @execution_time_tracking(platform=IntegrationType.QUICKBOOKS)
    async def _create_receipt(
        self, receipt_input_data: QuickbooksSyncInvoiceSchema
    ):
        create_receipt_response = await self._make_call(
            method="post",
            url_path=f"/v3/company/{self.realm_id}/purchase",
            headers=self.headers,
            json={
                "CurrencyRef": {"value": receipt_input_data.currency},
                "AccountRef": {"value": receipt_input_data.payment_source},
                "PaymentType": "Cash",
                "EntityRef": {
                    "type": "Vendor",
                    "value": receipt_input_data.vendor_id,
                },
                "DocNumber": receipt_input_data.invoice_id,
                "TxnDate": receipt_input_data.date_payment_due.isoformat(),
                "PrivateNote": receipt_input_data.memo,
                "GlobalTaxCalculation": (
                    "TaxExcluded"
                    if receipt_input_data.vat_exclusive
                    else "TaxInclusive"
                ),
                "Line": [
                    {
                        "Amount": self.calculate_transaction_amount(
                            receipt_input_data.vat_exclusive, line
                        ),
                        "DetailType": "AccountBasedExpenseLineDetail",
                        "AccountBasedExpenseLineDetail": {
                            "AccountRef": {"value": line.account_category},
                            "TaxCodeRef": (
                                {"value": line.tax_type}
                                if line.tax_type
                                else None
                            ),
                        },
                        "Description": line.description,
                    }
                    for line in receipt_input_data.line_items
                ],
            },
        )

        if create_receipt_response.status_code != codes.OK:
            logger.error(
                "QuickBooks: Failed to create a receipt",
                extra={
                    "receipt_data": receipt_input_data.model_dump(),
                },
            )
            raise AccountingIntegrationFailedToCreateReceiptException(
                "Failed to create receipt in QuickBooks"
            )

        create_receipt_response_data = create_receipt_response.json()[
            "Purchase"
        ]
        created_receipt = IntegrationReceipt(
            platform_record_id=create_receipt_response_data["Id"],
            company_id=self.company_id,
            date=create_receipt_response_data["TxnDate"],
            total_amount=(
                total_amount := create_receipt_response_data["TotalAmt"]
            ),
            tax_amount=(
                tax_amount := create_receipt_response_data.get(
                    "TxnTaxDetail", {}
                ).get("TotalTax", 0)
            ),
            net_amount=(total_amount - tax_amount),
            raw=create_receipt_response_data,
            currency=create_receipt_response_data.get("CurrencyRef", {}).get(
                "name"
            ),
            line_items=[
                IntegrationLineItem(
                    platform_record_id=line.get("Id"),
                    company_id=self.company_id,
                    total_amount=line.get("Amount"),
                    net_amount=0,
                    unit_price=0,
                    integration=self.platform_name,
                    raw=line,
                )
                for line in create_receipt_response_data.get("Line", [])
                if line.get("DetailType") == "AccountBasedExpenseLineDetail"
            ],
            integration=self.platform_name,
            vendor=create_receipt_response_data.get("VendorRef", {}).get(
                "name"
            ),
        )
        return created_receipt

    async def get_bank_accounts(self, *_, **__):
        return 0, []

    # pylint: disable=line-too-long
    async def get_vat_registered_status(self) -> bool:
        """
        Check if the company is VAT registered
        API docs link: https://developer.intuit.com/app/developer/qbo/docs/api/accounting/all-entities/taxagency
        :return: bool
        """
        tax_agency_response = await self._make_call(
            method="get",
            url_path=f"/v3/company/{self.realm_id}/query",
            params={
                "query": "select * from TaxAgency",  # nosec
                "minorversion": 75,
            },
            headers=self.headers,
        )

        tax_agencies = (
            tax_agency_response.json()
            .get("QueryResponse", {})
            .get("TaxAgency", [])
        )

        return any(
            agency.get("TaxTrackedOnSales")
            and agency.get("TaxTrackedOnPurchases")
            and agency.get("DisplayName") == "HM Revenue & Customs (VAT)"
            for agency in tax_agencies
        )

    @execution_time_tracking(platform=IntegrationType.QUICKBOOKS)
    async def get_organization_info(self) -> IntegrationOrganizationInfo:
        realm_id = await self.get_connected_client_id()
        company_preferences = await self._make_call(
            method="get",
            url_path=f"/v3/company/{realm_id}/preferences",
            headers=self.headers,
        )
        currency_preferences = (
            company_preferences.json()
            .get("Preferences", {})
            .get("CurrencyPrefs", {})
        )
        return IntegrationOrganizationInfo(
            is_vat_registered=await self.get_vat_registered_status(),
            has_multicurrency_enabled=currency_preferences.get(
                "MultiCurrencyEnabled"
            ),
            home_currency=currency_preferences.get("HomeCurrency").get(
                "value"
            ),
        )
