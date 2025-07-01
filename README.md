# SSO Integration for Frappe/ERPNext v15

A production-ready Single Sign-On (SSO) integration app for Frappe/ERPNext v15.
Allows seamless login from Laravel (or any external app) to ERPNext using secure HMAC tokens, with automatic user and employee creation.

---

## Features

- HMAC-SHA256 token validation
- Automatic user and employee creation
- Role assignment and session management
- Integration with HRMS, LMS, Wiki, Gameplan, Raven (if installed)
- Security: token expiry, IP/domain restriction, logging
- API endpoints for login, logout, token validation, user info

---

## Installation

1. **Get the app:**

   ```sh
   cd ~/frappe-bench/apps
   git clone https://github.com/abdullahdheir/sso_integration.git
   ```

2. **Install on your site:**

   ```sh
   bench --site yoursite install-app sso_integration
   ```

3. **Migrate:**
   ```sh
   bench --site yoursite migrate
   ```

---

## Configuration

1. **Go to Desk > SSO Settings**
2. Fill in:
   - **Enable SSO**
   - **Laravel App URL**
   - **Shared Secret Key** (must match your Laravel .env)
   - **Token Expiry Minutes** (default: 15)
   - **Auto Create Users/Employees** (recommended: enabled)
   - **Default User Type/Role**
   - **Allowed Email Domains** (comma separated, optional)
   - **Enable IP Restriction** and **Allowed IP Addresses** (optional)
   - **Redirect After Login** (default: `/app`)
   - **Enable Logging** (recommended: enabled)
   - **Send Welcome Email** (recommended: enabled)

---

## Laravel Integration Example

**Controller:**

```php
public function login(Request $request)
{
    $secret = env('ERP_SSO_SECRET');
    $erpUrl = env('ERP_SSO_URL');
    $payload = [
        'email' => $request->user()->email,
        'full_name' => $request->user()->name,
        'department' => $request->user()->department ?? null,
        'designation' => $request->user()->designation ?? null,
        'exp' => time() + (env('ERP_SSO_EXPIRY', 15) * 60),
        'iat' => time(),
        'source' => 'laravel_app'
    ];
    $token = json_encode($payload);
    $signature = hash_hmac('sha256', $token, $secret);
    $query = http_build_query(['token' => $token, 'signature' => $signature]);
    return redirect("{$erpUrl}?{$query}");
}
```

**.env:**

```
ERP_SSO_SECRET=your_shared_secret
ERP_SSO_URL=https://erp.yourdomain.com/api/method/sso_integration.api.sso_login
ERP_SSO_EXPIRY=15
```

---

## API Endpoints

- `/api/method/sso_integration.api.sso_login` (POST/GET)
- `/api/method/sso_integration.api.validate_token`
- `/api/method/sso_integration.api.sso_logout`
- `/api/method/sso_integration.api.user_info`

---

## Security Best Practices

- Use a strong, random shared secret
- Enable HTTPS
- Restrict allowed domains/IPs
- Monitor logs for suspicious activity
- Keep your app up to date

---

## Troubleshooting

- Check Frappe logs for SSO errors
- Ensure server times are synchronized
- Verify shared secret and allowed domains/IPs
- Test with valid/invalid tokens

---

## Contributing

Pull requests are welcome! Please open an issue first to discuss major changes.

---

## License

MIT

---

**Maintainer:** Eng. Abdullah Dheir
abdullah.dheir@gmail.com
