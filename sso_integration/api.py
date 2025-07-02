import frappe
from frappe import _
from frappe.utils.response import build_response
from .auth import sso_authenticate, SSOAuthError, validate_token
import json


@frappe.whitelist(allow_guest=True)
def sso_login(token, signature):
    """Main SSO login handler. Redirects to app after successful login."""
    try:
        # Check if a user is already logged in
        current_user = frappe.session.user if hasattr(
            frappe, 'session') else None
        payload, settings = validate_token(
            token, signature, frappe.local.request_ip)
        sso_email = payload['email'].lower()
        if current_user and current_user != 'Guest' and current_user.lower() != sso_email:
            # Logout the current user
            from frappe.auth import LoginManager
            LoginManager().logout()
            frappe.set_user(sso_email)
        user, settings = sso_authenticate(
            token, signature, frappe.local.request_ip, return_settings=True)
        redirect_url = settings.redirect_after_login or '/app'
        frappe.local.response["type"] = "redirect"
        frappe.local.response["location"] = redirect_url
        return
    except SSOAuthError as e:
        frappe.local.response['http_status_code'] = 401
        return {
            'status': 'error',
            'message': str(e),
            'message_ar': 'فشل تسجيل الدخول عبر الدخول الموحد.'
        }
    except Exception as e:
        frappe.local.response['http_status_code'] = 500
        return {
            'status': 'error',
            'message': _('Internal server error.'),
            'message_ar': 'حدث خطأ داخلي.'
        }


@frappe.whitelist(allow_guest=True)
def validate_token_api(token, signature):
    """Validate SSO token and signature."""
    try:
        payload = validate_token(token, signature, frappe.local.request_ip)
        return {'status': 'success', 'payload': payload}
    except SSOAuthError as e:
        frappe.local.response['http_status_code'] = 401
        return {'status': 'error', 'message': str(e)}
    except Exception as e:
        frappe.local.response['http_status_code'] = 500
        return {'status': 'error', 'message': _('Internal server error.')}


@frappe.whitelist(allow_guest=True)
def sso_logout():
    """Logout the current user."""
    frappe.local.login_manager.logout()
    return {'status': 'success', 'message': _('Logged out.')}


@frappe.whitelist(allow_guest=True)
def user_info():
    """Get current user info."""
    if frappe.session.user == 'Guest':
        return {'status': 'error', 'message': _('Not logged in.')}
    user = frappe.get_doc('User', frappe.session.user)
    return {
        'status': 'success',
        'user': {
            'email': user.email,
            'full_name': user.full_name,
            'roles': user.get_roles(),
            'user_type': user.user_type
        }
    }
