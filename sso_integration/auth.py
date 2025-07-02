import frappe
import hmac
import hashlib
import secrets
import time
import json
import traceback
from frappe.utils.password import get_decrypted_password
from frappe.utils import cint, now_datetime
from frappe.auth import LoginManager
from frappe import _


class SSOAuthError(Exception):
    pass


def log_sso_event(email, status, message, data=None):
    """Log SSO attempts for auditing and debugging."""
    if frappe.db.count('SSO Settings') > 0:
        frappe.logger('sso_integration').info({
            'email': email,
            'status': status,
            'message': message,
            'data': data or {}
        })


def get_sso_settings_from_request():
    request = frappe.local.request
    frappe.logger('sso_integration').info(
        {'headers': dict(request.headers), 'form_dict': dict(frappe.local.form_dict)})
    laravel_url = request.headers.get('Origin')
    frappe.logger('sso_integration').info(
        {'step': 'Origin header', 'laravel_url': laravel_url})
    if not laravel_url:
        laravel_url = request.headers.get('Referer')
        frappe.logger('sso_integration').info(
            {'step': 'Referer header', 'laravel_url': laravel_url})
    if not laravel_url:
        laravel_url = frappe.local.form_dict.get('laravel_app_url')
        frappe.logger('sso_integration').info(
            {'step': 'Query param', 'laravel_url': laravel_url})
    if laravel_url and laravel_url.startswith('"') and laravel_url.endswith('"'):
        laravel_url = laravel_url[1:-1]
        frappe.logger('sso_integration').info(
            {'step': 'Stripped quotes', 'laravel_url': laravel_url})
    if not laravel_url:
        frappe.logger('sso_integration').error(
            {'error': 'Could not determine Laravel App URL from request headers or query string.'})
        raise SSOAuthError(
            _('Could not determine Laravel App URL from request headers or query string.'))
    laravel_url = laravel_url.split('?')[0].rstrip('/')
    frappe.logger('sso_integration').info(
        {'step': 'Final laravel_url', 'laravel_url': laravel_url})
    filters = {'laravel_app_url': laravel_url}
    sso_settings = frappe.get_all(
        'SSO Settings', filters=filters, fields=['name'], limit=1)
    if not sso_settings:
        frappe.logger('sso_integration').error(
            {'error': 'No matching SSO Settings found', 'laravel_url': laravel_url})
        raise SSOAuthError(
            _('No matching SSO Settings found for this Laravel App URL: {}').format(laravel_url))
    return frappe.get_doc('SSO Settings', sso_settings[0].name)


def constant_time_compare(val1, val2):
    return hmac.compare_digest(val1, val2)


def validate_token(token, signature, ip=None):
    settings = get_sso_settings_from_request()
    secret = get_decrypted_password(
        'SSO Settings', settings.name, 'shared_secret_key', raise_exception=True)
    expected_sig = hmac.new(
        secret.encode(), token.encode(), hashlib.sha256).hexdigest()
    if not constant_time_compare(signature, expected_sig):
        raise SSOAuthError(_('Invalid signature.'))
    payload = json.loads(token)
    now = int(time.time())
    if now > payload['exp']:
        raise SSOAuthError(_('Token expired.'))
    if settings.enable_ip_restriction and ip:
        allowed_ips = [x.strip() for x in (
            settings.allowed_ip_addresses or '').split(',') if x.strip()]
        if ip not in allowed_ips:
            raise SSOAuthError(_('IP address not allowed.'))
    allowed_domains = [x.strip().lower() for x in (
        settings.allowed_email_domains or '').split(',') if x.strip()]
    if allowed_domains and not any(payload['email'].lower().endswith('@'+d) for d in allowed_domains):
        raise SSOAuthError(_('Email domain not allowed.'))
    return payload, settings


def get_or_create_user(payload, settings):
    email = payload['email'].lower()
    user = frappe.db.get('User', {'email': email})
    if user:
        return user
    if not settings.auto_create_users:
        raise SSOAuthError(
            _('User does not exist and auto-creation is disabled.'))
    user_doc = frappe.new_doc('User')
    user_doc.email = email
    user_doc.first_name = payload.get('full_name', email.split('@')[0])
    user_doc.user_type = settings.default_user_type or 'System User'
    user_doc.enabled = 1
    user_doc.new_password = secrets.token_urlsafe(16)
    user_doc.send_welcome_email = cint(settings.send_welcome_email)
    user_doc.insert(ignore_permissions=True)
    if settings.default_role:
        user_doc.add_roles(settings.default_role)
    frappe.db.commit()
    return user_doc


def create_employee_if_needed(user, payload, settings):
    if not frappe.get_installed_apps() or 'hrms' not in frappe.get_installed_apps():
        return
    if not settings.auto_create_employees:
        return
    if frappe.db.exists('Employee', {'user_id': user.email}):
        return
    company = frappe.db.get_single_value('Global Defaults', 'default_company')
    emp = frappe.new_doc('Employee')
    emp.employee_name = user.full_name or user.email
    emp.user_id = user.email
    emp.company = company
    emp.department = payload.get('department')
    emp.designation = payload.get('designation')
    emp.status = 'Active'
    emp.first_name = user.full_name or user.email
    emp.gender = payload.get('gender', 'Other')
    emp.date_of_birth = payload.get('date_of_birth', '2000-01-01')
    emp.date_of_joining = payload.get(
        'date_of_joining', frappe.utils.nowdate())
    emp.insert(ignore_permissions=True)
    frappe.db.commit()


def assign_integrations(user, payload, settings):
    # LMS
    if 'lms' in frappe.get_installed_apps():
        try:
            from lms.lms.doctype.learner.learner import create_learner_profile
            create_learner_profile(user.email)
        except Exception:
            pass
    # Wiki
    if 'wiki' in frappe.get_installed_apps():
        try:
            from wiki.wiki.doctype.wiki_settings.wiki_settings import set_default_permissions
            set_default_permissions(user.name)
        except Exception:
            pass
    # Gameplan
    if 'gameplan' in frappe.get_installed_apps():
        try:
            from gameplan.api import add_user_to_default_teams
            add_user_to_default_teams(user.email)
        except Exception:
            pass
    # Raven
    if 'raven' in frappe.get_installed_apps():
        try:
            from raven.api import add_user_to_company_channels
            add_user_to_company_channels(user.email)
        except Exception:
            pass


def login_user(user):
    login_manager = LoginManager()
    login_manager.authenticate(user=user.email)
    login_manager.post_login()
    frappe.local.login_manager = login_manager
    frappe.local.session.user = user.email
    frappe.local.session.sid = frappe.session.sid
    frappe.local.session.data['user'] = user.email
    frappe.local.session.data['user_type'] = user.user_type
    frappe.local.session.data['full_name'] = user.full_name
    frappe.db.commit()


def sso_authenticate(token, signature, ip=None):
    try:
        payload, settings = validate_token(token, signature, ip)
        user = get_or_create_user(payload, settings)
        create_employee_if_needed(user, payload, settings)
        assign_integrations(user, payload, settings)
        login_user(user)
        log_sso_event(user.email, 'success', 'SSO login successful', payload)
        return user
    except Exception as e:
        tb = traceback.format_exc()
        log_sso_event(payload.get('email', 'unknown') if 'payload' in locals(
        ) else 'unknown', 'failure', f'{str(e)}\\n{tb}')
        frappe.logger('sso_integration').error(
            {'error': str(e), 'traceback': tb})
        raise e
