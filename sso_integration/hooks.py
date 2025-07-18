app_name = "sso_integration"
app_title = "SSO Integration"
app_publisher = "Eng. Abdullah Dheir"
app_description = "Single Sign-On integration for Frappe/ERPNext v15"
app_email = "abdullah.dheir@gmail.com"
app_license = "MIT"

modules_list = ["SSO Integration"]

# Apps
# ------------------

# required_apps = []

# Each item in the list will be shown as an app in the apps page
# add_to_apps_screen = [
# 	{
# 		"name": "sso_integration",
# 		"logo": "/assets/sso_integration/logo.png",
# 		"title": "Sso Integration",
# 		"route": "/sso_integration",
# 		"has_permission": "sso_integration.api.permission.has_app_permission"
# 	}
# ]

# Includes in <head>
# ------------------

# include js, css files in header of desk.html
# app_include_css = "/assets/sso_integration/css/sso_integration.css"
# app_include_js = "/assets/sso_integration/js/sso_integration.js"

# include js, css files in header of web template
# web_include_css = "/assets/sso_integration/css/sso_integration.css"
# web_include_js = "/assets/sso_integration/js/sso_integration.js"

# include custom scss in every website theme (without file extension ".scss")
# website_theme_scss = "sso_integration/public/scss/website"

# include js, css files in header of web form
# webform_include_js = {"doctype": "public/js/doctype.js"}
# webform_include_css = {"doctype": "public/css/doctype.css"}

# include js in page
# page_js = {"page" : "public/js/file.js"}

# include js in doctype views
# doctype_js = {"doctype" : "public/js/doctype.js"}
# doctype_list_js = {"doctype" : "public/js/doctype_list.js"}
# doctype_tree_js = {"doctype" : "public/js/doctype_tree.js"}
# doctype_calendar_js = {"doctype" : "public/js/doctype_calendar.js"}

# Svg Icons
# ------------------
# include app icons in desk
# app_include_icons = "sso_integration/public/icons.svg"

# Home Pages
# ----------

# application home page (will override Website Settings)
# home_page = "login"

# website user home page (by Role)
# role_home_page = {
# 	"Role": "home_page"
# }

# Generators
# ----------

# automatically create page for each record of this doctype
# website_generators = ["Web Page"]

# Jinja
# ----------

# add methods and filters to jinja environment
# jinja = {
# 	"methods": "sso_integration.utils.jinja_methods",
# 	"filters": "sso_integration.utils.jinja_filters"
# }

# Installation
# ------------

# before_install = "sso_integration.install.before_install"
after_install = "sso_integration.install.after_install"

# Uninstallation
# ------------

# before_uninstall = "sso_integration.uninstall.before_uninstall"
# after_uninstall = "sso_integration.uninstall.after_uninstall"

# Integration Setup
# ------------------
# To set up dependencies/integrations with other apps
# Name of the app being installed is passed as an argument

# before_app_install = "sso_integration.utils.before_app_install"
# after_app_install = "sso_integration.utils.after_app_install"

# Integration Cleanup
# -------------------
# To clean up dependencies/integrations with other apps
# Name of the app being uninstalled is passed as an argument

# before_app_uninstall = "sso_integration.utils.before_app_uninstall"
# after_app_uninstall = "sso_integration.utils.after_app_uninstall"

# Desk Notifications
# ------------------
# See frappe.core.notifications.get_notification_config

# notification_config = "sso_integration.notifications.get_notification_config"

# Permissions
# -----------
# Permissions evaluated in scripted ways

# permission_query_conditions = {
# 	"Event": "frappe.desk.doctype.event.event.get_permission_query_conditions",
# }
#
# has_permission = {
# 	"Event": "frappe.desk.doctype.event.event.has_permission",
# }

# DocType Class
# ---------------
# Override standard doctype classes

# override_doctype_class = {
# 	"ToDo": "custom_app.overrides.CustomToDo"
# }

# Document Events
# ---------------
# Hook on document methods and events

doc_events = {
    "User": {
        "before_insert": "sso_integration.sso_integration.user_events.before_insert",
        "after_insert": "sso_integration.sso_integration.user_events.after_insert"
    }
}

# Scheduled Tasks
# ---------------

scheduler_events = {
    # 'daily': ["sso_integration.sso_integration.tasks.cleanup_expired_tokens"]
}

# Testing
# -------

# before_tests = "sso_integration.install.before_tests"

# Overriding Methods
# ------------------------------
#
# override_whitelisted_methods = {
# 	"frappe.desk.doctype.event.event.get_events": "sso_integration.event.get_events"
# }
#
# each overriding function accepts a `data` argument;
# generated from the base implementation of the doctype dashboard,
# along with any modifications made in other Frappe apps
# override_doctype_dashboards = {
# 	"Task": "sso_integration.task.get_dashboard_data"
# }

# exempt linked doctypes from being automatically cancelled
#
# auto_cancel_exempted_doctypes = ["Auto Repeat"]

# Ignore links to specified DocTypes when deleting documents
# -----------------------------------------------------------

# ignore_links_on_delete = ["Communication", "ToDo"]

# Request Events
# ----------------
# before_request = ["sso_integration.utils.before_request"]
# after_request = ["sso_integration.utils.after_request"]

# Job Events
# ----------
# before_job = ["sso_integration.utils.before_job"]
# after_job = ["sso_integration.utils.after_job"]

# User Data Protection
# --------------------

# user_data_fields = [
# 	{
# 		"doctype": "{doctype_1}",
# 		"filter_by": "{filter_by}",
# 		"redact_fields": ["{field_1}", "{field_2}"],
# 		"partial": 1,
# 	},
# 	{
# 		"doctype": "{doctype_2}",
# 		"filter_by": "{filter_by}",
# 		"partial": 1,
# 	},
# 	{
# 		"doctype": "{doctype_3}",
# 		"strict": False,
# 	},
# 	{
# 		"doctype": "{doctype_4}"
# 	}
# ]

# Authentication and authorization
# --------------------------------

# auth_hooks = [
# 	"sso_integration.auth.validate"
# ]

website_route_rules = [
    {'from_route': '/api/method/sso_integration.api.sso_login', 'to_route': 'sso-login'},
    {'from_route': '/api/method/sso_integration.api.validate_token',
        'to_route': 'sso-validate-token'},
    {'from_route': '/api/method/sso_integration.api.sso_logout',
        'to_route': 'sso-logout'},
    {'from_route': '/api/method/sso_integration.api.user_info',
        'to_route': 'sso-user-info'},
]

# Automatically update python controller files with type annotations for this app.
# export_python_type_annotations = True

# default_log_clearing_doctypes = {
# 	"Logging DocType Name": 30  # days to retain logs
# }
