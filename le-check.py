#!/usr/bin/python3

import ssl
import sys
import socket
import urllib.parse
import certifi
import OpenSSL.crypto as crypto
import datetime
import smtplib
import configparser
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


def read_config():
    """
    Read configuration from the config.ini file.

    If the config file doesn't exist, a default one will be created.
    The config file contains email settings and notification preferences.

    Returns:
        configparser.ConfigParser: The configuration object.
    """
    config = configparser.ConfigParser()
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.ini')

    # Check if a config file exists, if not create default config
    if not os.path.exists(config_path):
        config['email'] = {
            'smtp_server': 'smtp.example.com',
            'smtp_port': '587',
            'sender_email': 'alerts@example.com',
            'receiver_email': 'admin@example.com',
            'username': '',
            'password': ''
        }
        config['notification'] = {
            'days_before_expiry': '14'
        }
        with open(config_path, 'w') as configfile:
            config.write(configfile)
        print(f"Created default config file at {config_path}")

    config.read(config_path)
    return config


def send_email_notification(urls_expiring_soon, days_before_expiry):
    """
    Send an email notification for certificates expiring in the configured number of days.

    Email settings are read from the config.ini file. Username and password are optional.
    If they are not provided, the script will attempt to send the email without authentication.
    """
    # Read email configuration from the config file
    config = read_config()

    # Email configuration from config file
    smtp_server = config.get('email', 'smtp_server')
    smtp_port = config.getint('email', 'smtp_port')
    sender_email = config.get('email', 'sender_email')
    receiver_email = config.get('email', 'receiver_email')
    username = config.get('email', 'username', fallback='')
    password = config.get('email', 'password', fallback='')

    # Create email content
    subject = f"Certificate Expiration Warning - {len(urls_expiring_soon)} Certificates Expiring in {days_before_expiry} Days"

    # Create a message body with a table-like format for better readability
    body = f"The following SSL certificates will expire in {days_before_expiry} days:\n\n"
    body += "+-" + "-" * 50 + "-+-" + "-" * 12 + "-+\n"
    body += "| " + "URL".ljust(50) + " | " + "Expiry Date" + " |\n"
    body += "+-" + "-" * 50 + "-+-" + "-" * 12 + "-+\n"

    for url, expiry_date in urls_expiring_soon:
        body += f"| {url[:50].ljust(50)} | {expiry_date.strftime('%Y-%m-%d')} |\n"

    body += "+-" + "-" * 50 + "-+-" + "-" * 12 + "-+\n\n"
    body += "Please take action to renew these certificates."

    # Set up the email
    message = MIMEMultipart()
    message["From"] = sender_email
    message["To"] = receiver_email
    message["Subject"] = subject

    # Add body to email
    message.attach(MIMEText(body, "plain"))

    try:
        # Create an SMTP session
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()  # Secure the connection

        # Only login if username and password are provided
        if username and password:
            server.login(username, password)
        elif username:  # If only a username is provided, use it as the login
            server.login(username, '')
        elif password:  # If only password is provided, use sender_email as the login
            server.login(sender_email, password)
        # If neither username nor password is provided, try to send without authentication

        # Send email
        server.send_message(message)
        server.quit()
        print(f"Email notification sent for {len(urls_expiring_soon)} certificates expiring in {days_before_expiry} days")
        return True
    except Exception as e:
        print(f"Failed to send email notification: {str(e)}")
        return False


def check_certificate(url):
    """Check if the URL uses a Let's Encrypt/Google Trust Services certificate and get expiration date."""
    # Parse the URL to get the hostname
    parsed_url = urllib.parse.urlparse(url)
    hostname = parsed_url.netloc

    # If no hostname or scheme is provided, skip
    if not hostname:
        return False, None, f"Invalid URL format: {url}"

    if not parsed_url.scheme:
        hostname = hostname.split(':')[0]  # Remove port if present

    try:
        context = ssl.create_default_context(cafile=certifi.where())

        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                # Get certificate
                cert_bin = ssock.getpeercert(binary_form=True)
                cert = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_bin)

                expiry_date = datetime.datetime.strptime(
                    cert.get_notAfter().decode('ascii'),
                    '%Y%m%d%H%M%SZ'
                )

                issuer = cert.get_issuer().get_components()
                for key, value in issuer:
                    if key == b'O' and b'Let\'s Encrypt' in value or key == b'O' and b'Google Trust Services' in value:
                        return True, expiry_date, None

                # If we get here, it's not a Let's Encrypt cert
                return False, expiry_date, None

    except Exception as e:
        return False, None, f"Error checking {url}: {str(e)}"


def process_certificate(url, is_letsencrypt, expiry_date, current_time, min_info, expiring_soon, days_before_expiry):
    """
    Process certificate information for a URL.

    Checks if the certificate is expiring in the configured number of days and
    updates the list of certificates expiring soon if it is.

    Args:
        url: The URL being checked
        is_letsencrypt: Whether the certificate is from Let's Encrypt/Google Trust Services
        expiry_date: The expiration date of the certificate
        current_time: The current time
        min_info: Tuple containing information about the certificate with the least time left
        expiring_soon: List to store URLs with certificates expiring soon
        days_before_expiry: Number of days before expiry to check for

    Returns:
        Tuple containing updated min_info
    """
    if not expiry_date:
        print(f'URL {"is" if is_letsencrypt else "is not"} on LE/GTS: {url}')
        return min_info

    # Calculate days left once
    days_left = (expiry_date - current_time).days

    # Print certificate information
    cert_type = "LE/GTS" if is_letsencrypt else "not on LE"
    print(f'URL is {cert_type}: {url} - Certificate expires on {expiry_date.strftime("%Y-%m-%d")} ({days_left} days remaining)')

    # Check if the certificate is expiring in exactly the configured number of days
    if days_left == days_before_expiry:
        expiring_soon.append((url, expiry_date))

    # Update minimum days left if this URL has less time remaining
    min_days_left, min_days_url, min_expiry_date = min_info
    if days_left < min_days_left:
        return days_left, url, expiry_date

    return min_info


def main(file_path):
    """
    Read URLs from a file and print certificate expiration information for all URLs.

    Reads configuration from the config.ini file, including the number of days before
    certificate expiration to send a notification. Checks each URL for certificate
    expiration and sends an email notification if any certificates are expiring in
    the configured number of days.

    Args:
        file_path: Path to the file containing URLs to check
    """
    try:
        config = read_config()
        days_before_expiry = config.getint('notification', 'days_before_expiry')

        with open(file_path, 'r') as file:
            urls = [line.strip() for line in file if line.strip()]

        print(f"Checking {len(urls)} URLs for certificate expiration information...")
        print(f"Will notify about certificates expiring in {days_before_expiry} days")

        # Get current time once to ensure consistency
        current_time = datetime.datetime.now()

        # Variables to track the URL with the least time left
        min_info = (float('inf'), None, None)

        # List to track URLs with certificates expiring in the configured number of days
        expiring_soon = []

        for url in urls:
            is_letsencrypt, expiry_date, error = check_certificate(url)

            if error:
                print(f"{url} - {error}")
            else:
                min_info = process_certificate(url, is_letsencrypt, expiry_date, current_time, min_info, expiring_soon, days_before_expiry)

        # Print summary of URL with the least time left
        min_days_left, min_days_url, min_expiry_date = min_info
        if min_days_url:
            print("\nSummary:")
            print(f"URL with the least time left: {min_days_url}")
            print(f"Expires on: {min_expiry_date.strftime('%Y-%m-%d')} ({min_days_left} days remaining)")

        # Send email notification if any certificates are expiring in the configured number of days
        if expiring_soon:
            print(f"\nFound {len(expiring_soon)} certificates expiring in {days_before_expiry} days.")
            send_email_notification(expiring_soon, days_before_expiry)

    except FileNotFoundError:
        print(f"File not found: {file_path}")
    except Exception as e:
        print(f"An error occurred: {str(e)}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 le-check.py urls.txt")
    else:
        main(sys.argv[1])