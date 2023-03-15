import requests
import json

NVD_API_BASE_URL = 'https://services.nvd.nist.gov/rest/json/cves/1.0'


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

    version_headers = [
        'Server',
        'X-Powered-By',
        'X-AspNet-Version',
        'X-AspNetMvc-Version'
    ]

    missing_headers = []
    found_version_headers = {}

    try:
        response = requests.get(url)
        response_headers = response.headers

        for header in headers_to_check:
            if header not in response_headers:
                missing_headers.append(header)

        for header in version_headers:
            if header in response_headers:
                found_version_headers[header] = response_headers[header]

    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")

    return missing_headers, found_version_headers


def query_nvd_cve(product, version):
    url = f"{NVD_API_BASE_URL}?cpeMatchString=cpe:2.3:a:*:{product}:{version}:*:*:*:*:*:*:*"
    try:
        response = requests.get(url)
        response_data = json.loads(response.text)

        if response_data['totalResults'] > 0:
            return response_data['result']['CVE_Items']
        else:
            return None
    except requests.exceptions.RequestException as e:
        print(f"Error querying NVD API: {e}")
        return None


if __name__ == "__main__":
    url = input("Enter the URL of the web app: ").strip()
    missing_headers, found_version_headers = check_security_headers(url)

    if missing_headers:
        print("Missing security headers:")
        for header in missing_headers:
            print(f"- {header}")
    else:
        print("All security headers are present.")

    if found_version_headers:
        print("\nFound version headers:")
        for header, value in found_version_headers.items():
            print(f"- {header}: {value}")

    print("\nChecking for CVEs related to found version headers:")
    for header, value in found_version_headers.items():
        product_name = header.lower().replace('x-', '').replace('-', '_')
        print(f"\n{header}: {value}")

        cve_items = query_nvd_cve(product_name, value)
        if cve_items:
            print(f"Found {len(cve_items)} CVE(s):")
            for item in cve_items:
                print(f"- {item['cve']['CVE_data_meta']['ID']}: {item['cve']['description']['description_data'][0]['value']}")
        else:
            print("No CVEs found.")
