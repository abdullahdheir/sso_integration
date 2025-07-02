import frappe
from frappe.model.document import Document
from frappe import _


class SSOSettings(Document):
    """
    SSO Settings DocType for multiple SSO configurations.
    """

    def validate(self):
        if self.enable_ip_restriction and not self.allowed_ip_addresses:
            frappe.throw(
                _('Allowed IP Addresses required if IP restriction is enabled.'))
        if not self.shared_secret_key:
            frappe.throw(_('Shared Secret Key is required.'))
        if self.allowed_email_domains:
            self.allowed_email_domains = ','.join(
                [d.strip().lower() for d in self.allowed_email_domains.split(',') if d.strip()])
        if self.allowed_ip_addresses:
            self.allowed_ip_addresses = ','.join(
                [ip.strip() for ip in self.allowed_ip_addresses.split(',') if ip.strip()])
        # Uniqueness validation for sso_name and laravel_app_url
        if frappe.db.exists('SSO Settings', {'sso_name': self.sso_name, 'name': ('!=', self.name)}):
            frappe.throw(_('SSO Name must be unique.'))
        if frappe.db.exists('SSO Settings', {'laravel_app_url': self.laravel_app_url, 'name': ('!=', self.name)}):
            frappe.throw(_('Laravel App URL must be unique.'))