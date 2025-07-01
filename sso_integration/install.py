import frappe


def after_install():
    """Set up default SSO Settings after app install."""
    if not frappe.db.exists('DocType', 'SSO Settings'):
        return
    if not frappe.db.exists('SSO Settings'):
        doc = frappe.new_doc('SSO Settings')
        doc.enable_sso = 0
        doc.token_expiry_minutes = 15
        doc.auto_create_users = 1
        doc.auto_create_employees = 1
        doc.default_user_type = 'System User'
        doc.default_role = 'Employee'
        doc.enable_logging = 1
        doc.send_welcome_email = 1
        doc.redirect_after_login = '/app'
        doc.insert(ignore_permissions=True)
