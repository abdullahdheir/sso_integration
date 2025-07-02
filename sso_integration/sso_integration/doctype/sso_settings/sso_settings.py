import frappe
from frappe.model.document import Document
from frappe import _


class SSOSettings(Document):
    def validate(self):
        if self.enable_ip_restriction and not self.allowed_ip_addresses:
            frappe.throw(
                _('Allowed IP Addresses required if IP restriction is enabled.'))
        if self.enable_sso and not self.shared_secret_key:
            frappe.throw(_('Shared Secret Key is required if SSO is enabled.'))
        if self.allowed_email_domains:
            self.allowed_email_domains = ','.join(
                [d.strip().lower() for d in self.allowed_email_domains.split(',') if d.strip()])
        if self.allowed_ip_addresses:
            self.allowed_ip_addresses = ','.join(
                [ip.strip() for ip in self.allowed_ip_addresses.split(',') if ip.strip()])
