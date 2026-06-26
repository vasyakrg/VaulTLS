import time

import requests

from ui_helpers import pv_select

MAILHOG_API_URL = "http://mailhog:8025"


def wait_for_email(subject_keyword, timeout=10):
    start = time.time()
    while time.time() - start < timeout:
        res = requests.get(MAILHOG_API_URL + "/api/v2/messages")
        res.raise_for_status()
        messages = res.json().get("items", [])
        for msg in messages:
            subject = msg['Content']['Headers'].get('Subject', [''])[0]
            if subject_keyword in subject:
                return msg
        time.sleep(1)
    raise TimeoutError("Expected email not found")


def delete_all_emails():
    requests.delete(MAILHOG_API_URL + "/api/v1/messages")


def count_table_data_rows(page, table_selector=".active-certs"):
    # Count only tbody tr elements (excludes header rows in thead)
    rows = page.locator(f"{table_selector} tbody tr")
    return rows.count()


def test_certificates(page):
    delete_all_emails()

    page.goto("http://127.0.0.1/overview")
    page.wait_for_url("**/overview")
    assert "Certificates" in page.locator("h1").inner_text()
    page.click("#CreateCertificateButton")
    page.fill("#certName", "test_cert")
    pv_select(page, "userId", label="test")
    page.fill("#certPassword", "password")
    page.locator("#notify-user").check()
    page.click("button:has-text('Create Certificate')")
    page.click("#PasswordButton-1")
    assert "password" in page.locator("#PasswordInput-1").input_value()
    assert count_table_data_rows(page) == 1

    page.wait_for_timeout(1000)
    wait_for_email("VaulTLS: A new certificate is available")


def test_renewal_remind(page):
    delete_all_emails()

    page.goto("http://127.0.0.1/overview")
    page.wait_for_url("**/overview")
    page.click("#CreateCertificateButton")
    page.fill("#certName", "test_cert_remind")
    pv_select(page, "userId", label="test")
    page.fill("#certPassword", "password")
    page.fill("#validity", "0")
    pv_select(page, "validity_unit", label="Years")
    pv_select(page, "renewMethod", label="Remind")
    page.click("button:has-text('Create Certificate')")

    page.wait_for_timeout(5000)
    wait_for_email("VaulTLS: A certificate is about to expire")
    assert count_table_data_rows(page) == 2


def test_renewal_renew_notify(page):
    delete_all_emails()

    page.goto("http://127.0.0.1/overview")
    page.wait_for_url("**/overview")
    page.click("#CreateCertificateButton")
    page.fill("#certName", "test_cert_renew")
    pv_select(page, "userId", label="test")
    page.fill("#certPassword", "password")
    page.fill("#validity", "0")
    pv_select(page, "validity_unit", label="Years")
    pv_select(page, "renewMethod", label="Renew and Notify")
    page.click("button:has-text('Create Certificate')")

    page.wait_for_timeout(5000)

    wait_for_email("VaulTLS: A certificate was renewed")
    page.reload()
    page.wait_for_timeout(1000)
    assert count_table_data_rows(page) == 4


def test_users(page):
    page.goto("http://127.0.0.1/users")
    page.wait_for_url("**/users")
    assert "Users" in page.locator("h1").inner_text()
    page.click("#CreateUserButton")
    page.fill("#user_name", "test2")
    page.fill("#user_email", "test2@example.com")
    page.fill("#password", "password")
    page.click("button:has-text('Create User')")
    assert "test2" in page.locator("#UserName-2").inner_text()


def test_oidc(context):
    context.clear_cookies()
    page = context.new_page()

    page.goto("http://127.0.0.1/api/auth/oidc/login")
    page.fill("#username-textfield", "test")
    page.fill("#password-textfield", "password")
    page.click("#sign-in-button")

    page.click("#openid-consent-accept")
    page.wait_for_url("**/overview**")
    assert "Certificates" in page.locator("h1").inner_text()


def test_create_ca_and_certificate_with_ca_verification(page):
    """Test that creates a new CA, then a certificate using that CA, and verifies the correct CA was used"""
    page.goto("http://127.0.0.1/ca")
    page.wait_for_url("**/ca")
    assert "Certificate Authorities" in page.locator("h1").inner_text()

    initial_ca_count = count_table_data_rows(page, "table")

    page.click("#CreateCAButton")
    page.fill("#caName", "Test CA 2")
    page.fill("#validity", "5")
    pv_select(page, "validity_unit", label="Years")
    page.click("button:has-text('Create CA')")

    page.wait_for_timeout(2000)
    assert count_table_data_rows(page, "table") == initial_ca_count + 1

    # The CA list endpoint is public; resolve the new CA's id by name.
    cas = requests.get("http://127.0.0.1/api/certificates/ca").json()
    new_ca_id = next(c["id"] for c in cas if c["name"]["cn"] == "Test CA 2")

    page.goto("http://127.0.0.1/overview")
    page.wait_for_url("**/overview")

    initial_cert_count = count_table_data_rows(page)

    page.click("#CreateCertificateButton")
    page.fill("#certName", "test_cert_with_new_ca")
    pv_select(page, "userId", label="test")
    page.fill("#certPassword", "password")

    pv_select(page, "caId", label=f"(ID: {new_ca_id})", exact=False)

    page.click("button:has-text('Create Certificate')")

    page.wait_for_timeout(1000)

    assert count_table_data_rows(page) == initial_cert_count + 1

    new_cert_ca_id = page.locator("tbody tr").last.locator("[id^='CaId-']").inner_text()
    assert new_cert_ca_id == str(new_ca_id)
