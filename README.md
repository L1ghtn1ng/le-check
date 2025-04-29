# Certificate Expiration Checker

This script checks SSL certificates for a list of URLs and sends email notifications when certificates are about to expire.

## Features

- Checks SSL certificates for multiple URLs
- Identifies Let's Encrypt and Google Trust Services certificates
- Sends email notifications for certificates expiring in a configurable number of days
- Configurable email settings with optional authentication
- Provides a summary of the certificate with the least time remaining

## Configuration

The script uses a configuration file (`config.ini`) to store email settings and notification preferences. If the file doesn't exist, a default one will be created when the script runs.

### Email Configuration

In the `[email]` section of `config.ini`:

- `smtp_server`: SMTP server address (e.g., smtp.gmail.com)
- `smtp_port`: SMTP server port (e.g., 587 for TLS)
- `sender_email`: Email address to send notifications from
- `receiver_email`: Email address to send notifications to
- `username`: SMTP username (optional)
- `password`: SMTP password (optional)

If username and password are not provided, the script will attempt to send emails without authentication.

### Notification Configuration

In the `[notification]` section of `config.ini`:

- `days_before_expiry`: Number of days before certificate expiration to send a notification (default: 14)

## Usage

1. Create a file named `urls.txt` with one URL per line
2. Configure `config.ini` with your email settings and notification preferences
3. Run the script:

```
python le-check.py urls.txt
```

## Example Configuration

```ini
[email]
smtp_server = smtp.gmail.com
smtp_port = 587
sender_email = alerts@example.com
receiver_email = admin@example.com
# Optional settings - comment out or leave empty if not needed
username = your_username
password = your_password

[notification]
# Number of days before certificate expiration to send notification
days_before_expiry = 14
```

## Output

The script will:

1. Check each URL for certificate information
2. Print details about each certificate (issuer, expiration date, days remaining)
3. Print a summary of the certificate with the least time remaining
4. Send an email notification if any certificates are expiring in the configured number of days