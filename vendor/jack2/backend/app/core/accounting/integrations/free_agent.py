import base64
import urllib.parse

from httpx import codes

from app.core.accounting.constants import FREE_AGENT_CURRENCIES
from app.core.accounting.exceptions import (
    AccountingIntegrationCategoryNotAllowedException,
    AccountingIntegrationFailedToCreateCreditNoteException,
    AccountingIntegrationInvalidDataException,
    AccountingIntegrationInvalidExpenseCategoryDataException,
    AccountingIntegrationInvalidStockCategoryDataException,
    AccountingIntegrationInvalidTransactionDataException,
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
    CreateVendorSchema,
    IntegrationAccount,
    IntegrationAttachment,
    IntegrationCreditNote,
    IntegrationCurrency,
    IntegrationInvoice,
    IntegrationLineItem,
    IntegrationOrganizationInfo,
    IntegrationTaxCode,
    IntegrationTrackingCategorySchema,
    IntegrationType,
    IntegrationVendor,
)
from app.schemas.accounting.schemas import (
    FreeAgentSyncInvoiceSchema,
    FreeAgentTransactionExplanationSchema,
    IntegrationAccountClassification,
    IntegrationBusiness,
)

from .base import IntegrationBase


class FreeAgentIntegration(IntegrationBase):
    platform_name = IntegrationType.FREE_AGENT

    authorization_url = str(settings.FREE_AGENT_AUTHORIZATION_URL)
    scope = None
    token_url = str(settings.FREE_AGENT_TOKEN_URL)
    refresh_url = str(settings.FREE_AGENT_TOKEN_URL)
    base_url = str(settings.FREE_AGENT_BASE_URL)
    redirect_url = urllib.parse.urljoin(
        str(settings.DOMAIN), "/v2/integrations/callback/free_agent"
    )
    revoke_url = str(settings.FREE_AGENT_REVOKE_TOKEN_URL)
    client_id = settings.FREE_AGENT_CLIENT_ID
    client_secret = settings.FREE_AGENT_CLIENT_SECRET
    tenant_id: str | None = None
    tenant_name: str | None = None
    grant_type = "authorization_code"

    TAX_CODES_MAPPING = [
        {"band": "Zero rate", "percentage": 0, "sales_tax_status": None},
        {"band": "Reduced rate", "percentage": 5, "sales_tax_status": None},
        {"band": "Standard rate", "percentage": 20, "sales_tax_status": None},
        {"band": "Exempt", "percentage": 0, "sales_tax_status": "EXEMPT"},
        {
            "band": "Outside of the scope of VAT",
            "percentage": 0,
            "sales_tax_status": "OUT_OF_SCOPE",
        },
    ]

    EXCEPTION_MAPPING = {
        "bill_items.category can't be blank": AccountingIntegrationCategoryNotAllowedException,
        "cached_total_value is locked and cannot be changed": AccountingIntegrationInvalidTransactionDataException,
        "bill_items.category is not valid": AccountingIntegrationInvalidExpenseCategoryDataException,
        "bill_items.stock item must be specified to use this stock category": AccountingIntegrationInvalidStockCategoryDataException,
    }

    @property
    def headers(self):
        """Default API call headers"""
        if not self.tenant_id:
            logger.error(
                "Client subdomain was not set correctly for FreeAgent"
            )
            raise AccountingIntegrationTenantMissedException
        return {"Accept": "application/json", "X-Subdomain": self.tenant_id}

    def raise_for_api_errors(self, response_json: dict):
        errors = response_json.get("errors")
        if not errors:
            return

        if isinstance(errors, dict):
            error_message = errors.get("message")
        elif isinstance(errors, list) and "message" in errors[0]:
            error_message = errors[0]["message"]
        else:
            error_message = str(errors)

        exception_class = self.EXCEPTION_MAPPING.get(
            error_message, AccountingIntegrationInvalidDataException
        )
        logger.error(
            "FreeAgent: Error received from the integrations API %s",
            error_message,
        )

        if exception_class is AccountingIntegrationInvalidDataException:
            raise exception_class(error_message)
        raise exception_class

    async def get_connected_client_id(self):
        """Read realm ID from FreeAgent token"""
        if self.tenant_id:
            return self.tenant_id

        token = await self.fetch_auth_details()
        if realm_id := token.get("business_id"):
            self.tenant_id = realm_id
            return self.tenant_id
        raise OAuthIntegrationLoginRequiredException

    async def get_connected_client_name(self):
        """Read tenant name from FreeAgent auth details"""
        if self.tenant_name:
            return self.tenant_name

        auth_details = await self.fetch_auth_details()
        if tenant_name := auth_details.get("business_name"):
            self.tenant_name = tenant_name
            return tenant_name
        raise OAuthIntegrationLoginRequiredException

    async def set_company_name_and_id(self):
        auth_details = await self.fetch_auth_details()

        auth_details["tenant_id"] = self.tenant_id
        auth_details["tenant_name"] = self.tenant_name
        await self._store_auth_details(auth_details)

        logger.info(
            "Found tenant: %s. Tenant_id: %s",
            self.tenant_name,
            self.tenant_id,
        )

    @property
    def realm_id(self):
        if self.tenant_id:
            return self.tenant_id

        logger.error(
            "Tenant id was not set correctly for FreeAgentIntegrationClient"
        )
        raise AccountingIntegrationTenantMissedException

    @execution_time_tracking(platform=IntegrationType.FREE_AGENT)
    async def get_accounts(
        self, offset=0, limit=100, **kwargs
    ) -> tuple[int, list[IntegrationAccount]]:
        """
        Get accounts from FreeAgent
        API docs link: https://dev.freeagent.com/docs/categories
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
        page = (offset // limit) + 1

        mapping = {
            "admin_expenses_categories": IntegrationAccountClassification.EXPENSE,
            "cost_of_sales_categories": IntegrationAccountClassification.DIRECT_EXPENSES,
            "income_categories": IntegrationAccountClassification.OTHER_INCOME,
            "general_categories": IntegrationAccountClassification.OTHER_INCOME,
        }

        try:
            accounts_response = await self._make_call(
                method="get",
                url_path="/v2/categories",
                headers=self.headers,
                params={"page": page, "per_page": limit},
            )
        except OAuthIntegrationTooManyRequestsException as err:
            raise AccountingIntegrationTooManyRequestsException(
                response=err.response,
                retry_after=err.response.headers.get("retry-after", 300),
            )

        accounts_response = accounts_response.json()
        total = len(accounts_response)
        for category_type, classification in mapping.items():
            for category in accounts_response.get(category_type, []):
                tax_code = self._map_tax_code(
                    category.get("auto_sales_tax_rate")
                )
                accounts.append(
                    IntegrationAccount(
                        platform_record_id=category["url"],
                        name=category["description"],
                        description=category.get("tax_reporting_name"),
                        code=category["nominal_code"],
                        classification=classification,
                        type=category_type.replace("_categories", "").upper(),
                        integration=IntegrationType.FREE_AGENT,
                        company_id=self.company_id,
                        raw=category,
                        tax_code=tax_code,
                        platform_client_id=self.realm_id,
                    )
                )

        logger.info(
            "Retrieved %s accounts from %s for company_id=%s",
            len(accounts),
            self.platform_name.value,
            self.company_id,
        )
        return total, accounts

    def _map_tax_code(self, tax_band: str | None) -> IntegrationTaxCode | None:
        """Helper method to map tax band to IntegrationTaxCode."""
        if not tax_band:
            return None

        for tax_code in self.TAX_CODES_MAPPING:
            if tax_code["band"] == tax_band:
                return IntegrationTaxCode(
                    platform_record_id=tax_code["band"],
                    company_id=self.company_id,
                    display_tax_rate=str(tax_code["percentage"]),
                    effective_rate=tax_code["percentage"],
                    name=tax_code["band"],
                    raw=tax_code,
                    integration=self.platform_name,
                )
        return None

    @execution_time_tracking(platform=IntegrationType.FREE_AGENT)
    async def get_tax_codes(
        self, offset: int = 0, limit: int = 100, **_
    ) -> list[IntegrationTaxCode]:
        """Get Tax codes for FreeAgent."""
        logger.info(
            "Retrieving tax codes (offset=%s, limit=%s) from %s for company_id=%s",
            offset,
            limit,
            self.platform_name.value,
            self.company_id,
        )

        tax_codes = [
            IntegrationTaxCode(
                platform_record_id=tax_code["band"],
                company_id=self.company_id,
                display_tax_rate=str(tax_code["percentage"]),
                effective_rate=tax_code["percentage"],
                name=tax_code["band"],
                raw=tax_code,
                integration=self.platform_name,
            )
            for tax_code in self.TAX_CODES_MAPPING
        ]

        logger.info(
            "Retrieved %s tax codes from %s for company_id=%s",
            len(tax_codes),
            self.platform_name.value,
            self.company_id,
        )

        return tax_codes

    @execution_time_tracking(platform=IntegrationType.FREE_AGENT)
    async def get_tracking_categories(
        self, offset=0, limit=100, **kwargs
    ) -> list[IntegrationTrackingCategorySchema]:
        """
        Get Tracking categories from FreeAgent
        API docs link: https://dev.freeagent.com/docs/projects
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
        tracking_categories = []
        # page = (offset // limit) + 1
        # try:
        #     projects_response = await self._make_call(
        #         method="get",
        #         url_path="/v2/projects",
        #         headers=self.headers,
        #         params={"page": page, "per_page": limit},
        #     )
        # except OAuthIntegrationTooManyRequestsException as err:
        #     raise AccountingIntegrationTooManyRequestsException(
        #         response=err.response,
        #         retry_after=err.response.headers.get("retry-after", 300),
        #     )
        #
        # tracking_categories_data = projects_response.json()
        # for tracking_category in tracking_categories_data.get("projects", []):
        #     tracking_categories.append(
        #         IntegrationTrackingCategorySchema(
        #             platform_record_id=tracking_category["url"],
        #             company_id=self.company_id,
        #             name=tracking_category["name"],
        #             raw=tracking_category,
        #             integration=self.platform_name,
        #             options=[],
        #         )
        #     )

        return tracking_categories

    @execution_time_tracking(platform=IntegrationType.FREE_AGENT)
    async def get_vendors(
        self, offset=0, limit=100, **kwargs
    ) -> list[IntegrationVendor]:
        """
        Get Vendors from FreeAgent
        API docs link: https://dev.freeagent.com/docs/contacts
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
        page = (offset // limit) + 1
        try:
            vendors_response = await self._make_call(
                method="get",
                url_path="/v2/contacts",
                headers=self.headers,
                params={"page": page, "per_page": limit},
            )
        except OAuthIntegrationTooManyRequestsException as err:
            raise AccountingIntegrationTooManyRequestsException(
                response=err.response,
                retry_after=err.response.headers.get("retry-after", 300),
            )

        vendors_data = vendors_response.json()
        for record in vendors_data.get("contacts", []):
            vendors.append(
                IntegrationVendor(
                    platform_record_id=record["url"],
                    company_id=self.company_id,
                    name=self.get_vendor_name(record),
                    raw=record,
                    integration=self.platform_name,
                )
            )

        return vendors

    @staticmethod
    def get_vendor_name(data: dict) -> str:
        if data.get("organisation_name"):
            return data["organisation_name"]

        first_name = data.get("first_name", "").strip()
        last_name = data.get("last_name", "").strip()

        if first_name and last_name:
            return f"{first_name} {last_name}"
        return first_name or last_name or ""

    @execution_time_tracking(platform=IntegrationType.FREE_AGENT)
    async def get_invoices(
        self, offset=0, limit=100, **kwargs
    ) -> list[IntegrationInvoice]:
        """
        Get Invoices from FreeAgent
        API docs link: https://dev.freeagent.com/docs/bills
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
        page = (offset // limit) + 1
        try:
            invoices_response = await self._make_call(
                method="get",
                url_path="/v2/bills",
                headers=self.headers,
                params={
                    "page": page,
                    "per_page": limit,
                    "nested_bill_items": True,
                },
            )
        except OAuthIntegrationTooManyRequestsException as err:
            raise AccountingIntegrationTooManyRequestsException(
                response=err.response,
                retry_after=err.response.headers.get("retry-after", 300),
            )

        invoices_records = invoices_response.json()
        for invoice in invoices_records.get("bills", []):
            try:
                attachments = await self.get_invoice_attachments(invoice)
            except OAuthIntegrationTooManyRequestsException as err:
                raise AccountingIntegrationTooManyRequestsException(
                    response=err.response,
                    retry_after=err.response.headers.get("retry-after", 300),
                )

            invoices.append(
                IntegrationInvoice(
                    platform_record_id=invoice["url"],
                    company_id=self.company_id,
                    due_date=invoice["due_on"],
                    date=invoice["dated_on"],
                    total_amount=invoice["total_value"],
                    tax_amount=0,
                    net_amount=invoice["net_value"],
                    vendor=invoice["contact"],
                    currency=invoice["currency"],
                    platform_client_id=self.realm_id,
                    line_items=[
                        IntegrationLineItem(
                            company_id=self.company_id,
                            unit_price=float(invoice_item["total_value"]),
                            quantity=1,
                            total_amount=float(invoice_item["total_value"]),
                            net_amount=float(
                                invoice_item["total_value_ex_tax"]
                            ),
                            tax_codes=[],
                            tax_included=False,
                            raw=invoice_item,
                            platform_client_id=self.realm_id,
                            integration=self.platform_name,
                        )
                        for invoice_item in invoice.get("invoice_items", [])
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

    async def _store_auth_details(
        self, auth_details: dict, expiry=3600
    ) -> None:
        expiry = auth_details["refresh_token_expires_in"]
        await super()._store_auth_details(auth_details, expiry)

    async def sync_invoice(
        self,
        invoice_details: FreeAgentSyncInvoiceSchema,
    ):
        await self._validate_invoice_data(invoice_details)
        if invoice_details.id:
            return await self._update_invoice(invoice_details)
        return await self._create_invoice(invoice_details)

    @execution_time_tracking(platform=IntegrationType.FREE_AGENT)
    async def _update_invoice(
        self, invoice_data: FreeAgentSyncInvoiceSchema
    ) -> IntegrationInvoice:
        """
        Update an invoice on FreeAgent
        API docs link: https://dev.freeagent.com/docs/bills
        """
        invoice_id = self.get_platform_id_from_url(invoice_data.id)
        existing_invoice = await self._make_call(
            method="get",
            url_path=f"/v2/bills/{invoice_id}",
            headers=self.headers,
        )
        if codes.is_error(existing_invoice.status_code):
            raise AccountingIntegrationInvalidDataException(
                "Failed to fetch document to update from FreeAgent"
            )

        existing_invoice_data = existing_invoice.json()

        update_invoice_response = await self._make_call(
            method="put",
            url_path=f"/v2/bills/{invoice_id}",
            headers=self.headers,
            json={
                "bill": {
                    "contact": invoice_data.contact_id,
                    "dated_on": invoice_data.date.isoformat(),
                    "reference": invoice_data.reference,
                    "due_on": (
                        invoice_data.due_date.isoformat()
                        if invoice_data.due_date
                        else None
                    ),
                    "bill_items": [
                        {
                            "url": "",
                            "category": li.account_category,
                            "description": li.description,
                            "total_value": li.total,
                            "sales_tax_rate": li.sales_tax_rate,
                            "sales_tax_status": next(
                                (
                                    tax["sales_tax_status"]
                                    for tax in self.TAX_CODES_MAPPING
                                    if tax["band"] == li.sales_tax_name
                                ),
                                None,
                            ),
                            "manual_sales_tax_amount": li.manual_sales_tax_amount,
                        }
                        for li in invoice_data.line_items
                    ]
                    + [
                        {"url": el["url"], "_destroy": 1}
                        for el in existing_invoice_data.get("bill", {}).get(
                            "bill_items", []
                        )
                    ],
                    "currency": invoice_data.currency,
                }
            },
        )
        update_invoice_response = update_invoice_response.json()
        self.raise_for_api_errors(response_json=update_invoice_response)

        invoice = update_invoice_response["bill"]
        invoice_updated = IntegrationInvoice(
            platform_record_id=invoice["url"],
            company_id=self.company_id,
            due_date=invoice["due_on"],
            date=invoice["dated_on"],
            total_amount=invoice["total_value"],
            tax_amount=0,
            net_amount=invoice["net_value"],
            vendor=invoice["contact"],
            currency=invoice["currency"],
            line_items=[
                IntegrationLineItem(
                    company_id=self.company_id,
                    unit_price=float(li["total_value"]),
                    quantity=1,
                    total_amount=float(li["total_value"]),
                    net_amount=float(li["total_value_ex_tax"]),
                    tax_codes=[],
                    raw=li,
                    integration=self.platform_name,
                )
                for li in invoice.get("bill_items", [])
            ],
            raw=invoice,
            integration=self.platform_name,
        )

        if invoice_data.status == "PAID":
            await self._create_payment(
                payment_data=FreeAgentTransactionExplanationSchema(
                    amount=invoice_updated.total_amount,
                    date=invoice_updated.due_date,
                    paid_bill=invoice_updated.platform_record_id,
                    bank_account=invoice_data.payment_source_platform_id,
                    currency=invoice_updated.currency,
                )
            )

        return invoice_updated

    @execution_time_tracking(platform=IntegrationType.FREE_AGENT)
    async def _create_payment(
        self, payment_data: FreeAgentTransactionExplanationSchema
    ):
        """
        Create bank transaction explanation on FreeAgent
        Docs: https://dev.freeagent.com/docs/bank_transaction_explanations
        """
        request_data = {
            "dated_on": payment_data.date.isoformat(),
            "paid_bill": payment_data.paid_bill,
            "bank_account": payment_data.bank_account,
        }
        if payment_data.currency != "GBP":
            request_data["foreign_currency_value"] = payment_data.amount
        else:
            request_data["gross_value"] = payment_data.amount

        create_transaction_explanation = await self._make_call(
            method="post",
            url_path="/v2/bank_transaction_explanations",
            headers=self.headers,
            json=request_data,
        )
        create_payment_response = create_transaction_explanation.json()
        self.raise_for_api_errors(response_json=create_payment_response)

        return create_payment_response

    @execution_time_tracking(platform=IntegrationType.FREE_AGENT)
    async def _create_invoice(
        self, invoice_data: FreeAgentSyncInvoiceSchema
    ) -> IntegrationInvoice:
        """
        Create an invoice on FreeAgent
        API docs link: https://dev.freeagent.com/docs/bills
        """
        create_invoice_response = await self._make_call(
            method="post",
            url_path="/v2/bills",
            headers=self.headers,
            json={
                "bill": {
                    "contact": invoice_data.contact_id,
                    "dated_on": invoice_data.date.isoformat(),
                    "reference": invoice_data.reference,
                    "due_on": (
                        invoice_data.due_date.isoformat()
                        if invoice_data.due_date
                        else None
                    ),
                    "bill_items": [
                        {
                            "category": li.account_category,
                            "description": li.description,
                            "total_value": li.total,
                            "sales_tax_rate": li.sales_tax_rate,
                            "sales_tax_status": next(
                                (
                                    tax["sales_tax_status"]
                                    for tax in self.TAX_CODES_MAPPING
                                    if tax["band"] == li.sales_tax_name
                                ),
                                None,
                            ),
                        }
                        for li in invoice_data.line_items
                    ],
                    "currency": invoice_data.currency,
                }
            },
        )
        create_invoice_response = create_invoice_response.json()
        self.raise_for_api_errors(response_json=create_invoice_response)

        invoice = create_invoice_response["bill"]
        created_invoice = IntegrationInvoice(
            platform_record_id=invoice["url"],
            company_id=self.company_id,
            due_date=invoice["due_on"],
            date=invoice["dated_on"],
            total_amount=invoice["total_value"],
            tax_amount=0,
            net_amount=invoice["net_value"],
            vendor=invoice["contact"],
            currency=invoice["currency"],
            line_items=[
                IntegrationLineItem(
                    company_id=self.company_id,
                    unit_price=float(li["total_value"]),
                    quantity=1,
                    total_amount=float(li["total_value"]),
                    net_amount=float(li["total_value_ex_tax"]),
                    tax_codes=[],
                    raw=li,
                    integration=self.platform_name,
                )
                for li in invoice.get("bill_items", [])
            ],
            raw=invoice,
            integration=self.platform_name,
        )

        if invoice_data.status == "PAID":
            await self._create_payment(
                payment_data=FreeAgentTransactionExplanationSchema(
                    amount=created_invoice.total_amount,
                    date=created_invoice.due_date,
                    paid_bill=created_invoice.platform_record_id,
                    bank_account=invoice_data.payment_source_platform_id,
                    currency=created_invoice.currency,
                )
            )

        return created_invoice

    async def get_tax_rates(self):
        return []

    @execution_time_tracking(platform=IntegrationType.FREE_AGENT)
    async def get_currencies(
        self, *_args, **_kwargs
    ) -> list[IntegrationCurrency]:
        """
        Get currencies from FreeAgent
        API docs link: https://dev.freeagent.com/docs/currencies
        :return: list of IntegrationCurrency objects
        """
        logger.info(
            "Retrieving currencies from %s for company_id=%s",
            self.platform_name.value,
            self.company_id,
        )

        currencies = []
        for currency in FREE_AGENT_CURRENCIES:
            currencies.append(
                IntegrationCurrency(
                    platform_record_id=currency["code"],
                    company_id=self.company_id,
                    code=currency["code"],
                    name=currency["name"],
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

    @execution_time_tracking(platform=IntegrationType.FREE_AGENT)
    async def add_attachment_to_document(
        self,
        invoice_id: str,
        file_obj: bytes,
        filename: str,
        document_type: str,
        *args,
        **kwargs,
    ) -> None:
        """
        Add attachment to the FreeAgent document
        API docs link: https://dev.freeagent.com/docs/bills
        :return: None
        """
        invoice_id = self.get_platform_id_from_url(invoice_id)
        await self._make_call(
            "put",
            url_path=f"/v2/bills/{invoice_id}",
            headers=self.headers,
            json={
                "bill": {
                    "attachment": {
                        "data": base64.b64encode(file_obj).decode(),
                        "file_name": filename,
                        "content_type": "application/x-pdf",
                    }
                }
            },
        )

    @execution_time_tracking(platform=IntegrationType.FREE_AGENT)
    async def create_vendor(
        self, vendor_data: CreateVendorSchema
    ) -> IntegrationVendor:
        """
        API docs link: https://dev.freeagent.com/docs/contacts
        return: IntegrationVendor
        """
        request_json = {
            "contact": {
                "organisation_name": vendor_data.name,
                "first_name": vendor_data.name,
                "sales_tax_registration_number": vendor_data.vat_number,
                "contact_name_on_invoices": True,
                "locale": "en",
            }
        }

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
                request_json["contact"][
                    "address1"
                ] = supplier_address.first_line
                request_json["contact"][
                    "address2"
                ] = supplier_address.second_line
                request_json["contact"]["postcode"] = supplier_address.postcode
                request_json["contact"]["town"] = supplier_address.city

        try:
            create_vendor_response = await self._make_call(
                method="post",
                url_path="/v2/contacts",
                headers=self.headers,
                json=request_json,
            )
            create_vendor_response = create_vendor_response.json()
            vendor = create_vendor_response["contact"]

            return IntegrationVendor(
                platform_record_id=vendor["url"],
                company_id=self.company_id,
                name=vendor["organisation_name"],
                raw=vendor,
                integration=self.platform_name,
            )
        except OAuthIntegrationBaseException as err:
            raise err

    @staticmethod
    def get_platform_id_from_url(url: str) -> str:
        return url.split("/")[-1]

    @execution_time_tracking(platform=IntegrationType.FREE_AGENT)
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

    @execution_time_tracking(platform=IntegrationType.FREE_AGENT)
    async def get_invoice_attachments(
        self, invoice: dict
    ) -> list[IntegrationAttachment] | None:
        platform_id = self.get_platform_id_from_url(invoice["url"])
        attachments = []

        get_attachments_response = await self._make_call(
            method="get",
            url_path=(f"/v2/bills/{platform_id}"),
            headers=self.headers,
        )
        attachments_response = get_attachments_response.json()

        bill = attachments_response["bill"]
        if not bill.get("attachment"):
            return []

        invoice_content = await self.get_attachment_content(
            bill["attachment"]["content_src"]
        )

        if not invoice_content:
            return []

        attachments.append(
            IntegrationAttachment(
                filename=(file_name := bill["attachment"]["file_name"]),
                mimetype=bill["attachment"]["content_type"],
                platform_record_id=bill["attachment"]["url"],
                content=invoice_content.encode(),
                raw=bill["attachment"],
                company_id=self.company_id,
                integration=self.platform_name,
                s3_path=f"{self.company_id}/{self.platform_name}/{file_name}",
            )
        )
        return attachments

    @execution_time_tracking(platform=IntegrationType.FREE_AGENT)
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
                url_path="/v2/clients",
                params={
                    "page": page,
                    "per_page": limit,
                },
            )
        except OAuthIntegrationTooManyRequestsException as err:
            raise AccountingIntegrationTooManyRequestsException(
                response=err.response,
                retry_after=err.response.headers.get("retry-after", 300),
            )

        businesses_response_data = businesses_response.json()
        for business in businesses_response_data["clients"]:
            businesses.append(
                IntegrationBusiness(
                    platform_record_id=business["subdomain"],
                    company_id=self.company_id,
                    name=business["name"],
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

    @execution_time_tracking(platform=IntegrationType.FREE_AGENT)
    async def _create_credit_note(
        self, credit_note_input_data: FreeAgentSyncInvoiceSchema
    ):
        create_credit_note_response = await self._make_call(
            method="post",
            url_path="/v2/credit_notes",
            headers=self.headers,
            params={"nested_credit_note_items": True},
            json={
                "credit_note": {
                    "contact": credit_note_input_data.contact_id,
                    "dated_on": credit_note_input_data.date.isoformat(),
                    "due_on": (
                        credit_note_input_data.due_date.isoformat()
                        if credit_note_input_data.due_date
                        else None
                    ),
                    "currency": credit_note_input_data.currency,
                    "payment_terms_in_days": 0,
                }
            },
        )
        if create_credit_note_response.status_code != codes.CREATED:
            logger.error(
                "FreeAgent: Failed to create a credit note",
                extra={
                    "credit_note_data": credit_note_input_data.model_dump(),
                    "response": create_credit_note_response,
                },
            )
            raise AccountingIntegrationFailedToCreateCreditNoteException(
                "Failed to create credit note in FreeAgent"
            )

        create_credit_note_response_data = create_credit_note_response.json()[
            "credit_note"
        ]
        created_credit_note = IntegrationCreditNote(
            platform_record_id=create_credit_note_response_data["url"],
            company_id=self.company_id,
            date=create_credit_note_response_data["dated_on"],
            due_date=create_credit_note_response_data["due_on"],
            total_amount=create_credit_note_response_data["total_value"],
            net_amount=create_credit_note_response_data["net_value"],
            currency=create_credit_note_response_data["currency"],
            raw=create_credit_note_response_data,
            line_items=[
                IntegrationLineItem(
                    platform_record_id=line["url"],
                    company_id=self.company_id,
                    net_amount=0,
                    unit_price=float(unit_price := line["price"]),
                    quantity=float(quantity := line["quantity"]),
                    description=line.get("description"),
                    total_amount=(unit_price * quantity),
                    integration=self.platform_name,
                    raw=line,
                )
                for line in create_credit_note_response_data.get(
                    "credit_note_items", []
                )
            ],
            integration=self.platform_name,
            vendor=create_credit_note_response_data["contact"],
        )
        if credit_note_input_data.status == "PAID":
            await self._create_payment(
                payment_data=FreeAgentTransactionExplanationSchema(
                    amount=created_credit_note.total_amount,
                    date=created_credit_note.due_date,
                    paid_bill=created_credit_note.platform_record_id,
                    bank_account=credit_note_input_data.payment_source_platform_id,  # pylint: disable=line-too-long
                    currency=credit_note_input_data.currency,
                )
            )
        return created_credit_note

    async def _create_receipt(
        self, receipt_input_data: FreeAgentSyncInvoiceSchema
    ):
        pass

    @execution_time_tracking(platform=IntegrationType.FREE_AGENT)
    async def get_bank_accounts(self, offset=0, limit=100, **kwargs):
        """
        Get bank accounts from FreeAgent
        API docs link: https://dev.freeagent.com/docs/bank_accounts
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
                url_path="/v2/bank_accounts",
                params={
                    "page": page,
                    "per_page": limit,
                },
                headers=self.headers,
            )
        except OAuthIntegrationTooManyRequestsException as err:
            raise AccountingIntegrationTooManyRequestsException(
                response=err.response,
                retry_after=err.response.headers.get("retry-after", 300),
            )

        response_data = response.json().get("bank_accounts", [])
        total = len(response_data)
        for account in response_data:
            bank_accounts.append(
                IntegrationAccount(
                    platform_record_id=account["url"],
                    company_id=self.company_id,
                    name=account["name"],
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

    async def test_tenant_connection(self):
        await self.get_connected_client_id()

        try:
            await self._make_call(
                method="get",
                url_path="/v2/company",
                headers=self.headers,
            )
        except OAuthIntegrationBaseException as err:
            logger.error(
                "Failed to get FreeAgent company info - %s",
                err,
                extra={"company_id": self.company_id},
            )
            await self.delete_auth_from_cache()
            raise OAuthIntegrationLoginRequiredException(
                f"You are not connected to {self.platform_name.value} "
                "currently, please reconnect in order to continue your work"
            )

    async def get_organization_info(self) -> IntegrationOrganizationInfo:
        await self.get_connected_client_id()

        response = await self._make_call(
            method="get",
            url_path="/v2/company",
            headers=self.headers,
        )
        company_data = response.json()["company"]
        return IntegrationOrganizationInfo(
            home_currency=company_data.get("currency"),
            has_multicurrency_enabled="currency"
            not in company_data.get("locked_attributes", []),
            is_vat_registered=company_data.get("sales_tax_registration_status")
            == "Registered",
        )
