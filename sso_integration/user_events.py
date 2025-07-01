"""
User DocType event handlers for SSO Integration.
"""
import frappe


def before_insert(doc, method=None):
    """Event: Before a User is inserted. Add custom SSO logic here if needed."""
    pass


def after_insert(doc, method=None):
    """Event: After a User is inserted. Add custom SSO logic here if needed."""
    pass
