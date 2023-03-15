import requests

def check_security_headers(url):
    headers_to_check = [
        'Strict-Transport-Security',
        'Content-Security-Policy',
        'X-Content-Type-Options',
        'X-Frame-Options',
        'X-XSS-Protection',
        'Referrer-Policy',
        'Permissions-Policy'
    ]

    missing_headers = []

    try:
        response = requests.get(url)
        response_headers = response.headers

        for header in headers_to_check:
            if header not in response_headers:
                missing_headers.append(header)

    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")

    return missing_headers

if __name__ == "__main__":
    url = input("Enter the URL of the web app: ").strip()
    missing_headers = check_security_headers(url)

    if missing_headers:
        print("Missing security headers:")
        for header in missing_headers:
            print(f"- {header}")
    else:
        print("All security headers are present.")
