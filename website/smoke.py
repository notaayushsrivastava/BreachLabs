"""BreachLabs Website - Smoke Tests.

Run with: python smoke.py
"""

import sys
import urllib.request
import urllib.error
import json

BASE_URL = 'http://127.0.0.1:8001'
TIMEOUT = 10

GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
BOLD = '\033[1m'
RESET = '\033[0m'

def print_header(text):
    print(f"\n{BOLD}{BLUE}{'=' * 60}{RESET}")
    print(f"{BOLD}{BLUE}{text.center(60)}{RESET}")
    print(f"{BOLD}{BLUE}{'=' * 60}{RESET}\n")

def print_result(test_name, passed, details=''):
    status = f"{GREEN}✓ PASS{RESET}" if passed else f"{RED}✗ FAIL{RESET}"
    print(f"  {status} - {test_name}")
    if details:
        print(f"         {details}")

def fetch_url(url, expect_json=False):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'BreachLabs-SmokeTest/1.0'})
        with urllib.request.urlopen(req, timeout=TIMEOUT) as response:
            status_code = response.getcode()
            content = response.read().decode('utf-8')
            if expect_json:
                try:
                    content = json.loads(content)
                except json.JSONDecodeError as e:
                    return False, status_code, None, f"JSON parse error: {e}"
            return True, status_code, content, None
    except urllib.error.HTTPError as e:
        return False, e.code, None, f"HTTP {e.code}"
    except urllib.error.URLError as e:
        return False, None, None, f"Connection error: {e.reason}"
    except Exception as e:
        return False, None, None, str(e)

def run_smoke_tests():
    results = {'tests_run': 0, 'tests_passed': 0, 'tests_failed': 0}
    
    print_header("BreachLabs Website Smoke Tests")
    
    # Test health endpoint
    print(f"{YELLOW}Testing Health Endpoint...{RESET}")
    success, status, content, error = fetch_url(f'{BASE_URL}/health')
    results['tests_run'] += 1
    if success and status == 200:
        results['tests_passed'] += 1
        print_result("Health endpoint returns 200", True)
    else:
        results['tests_failed'] += 1
        print_result("Health endpoint returns 200", False, error or f"Status: {status}")
    
    # Test API health
    print(f"{YELLOW}Testing API Health Endpoint...{RESET}")
    success, status, content, error = fetch_url(f'{BASE_URL}/api/health', expect_json=True)
    results['tests_run'] += 1
    if success and status == 200 and isinstance(content, dict):
        results['tests_passed'] += 1
        print_result("API health endpoint returns JSON", True)
    else:
        results['tests_failed'] += 1
        print_result("API health endpoint returns JSON", False, error or f"Status: {status}")
    
    # Test home page
    print(f"{YELLOW}Testing Home Page...{RESET}")
    success, status, content, error = fetch_url(f'{BASE_URL}/')
    results['tests_run'] += 1
    if success and status == 200:
        results['tests_passed'] += 1
        checks = [
            ('Has title tag', '<title>' in content),
            ('Has BreachLabs text', 'BreachLabs' in content),
            ('Has tagline', 'Build. Break. Verify. Fix' in content),
        ]
        for check_name, check_passed in checks:
            if check_passed:
                results['tests_passed'] += 1
                print_result(f"  Content check: {check_name}", True)
            else:
                results['tests_failed'] += 1
                print_result(f"  Content check: {check_name}", False)
            results['tests_run'] += 1
    else:
        results['tests_failed'] += 1
        print_result("Home page returns 200", False, error or f"Status: {status}")
    
    # Test features page
    print(f"{YELLOW}Testing Features Page...{RESET}")
    success, status, content, error = fetch_url(f'{BASE_URL}/features')
    results['tests_run'] += 1
    if success and status == 200 and 'Features' in content:
        results['tests_passed'] += 1
        print_result("Features page returns 200", True)
    else:
        results['tests_failed'] += 1
        print_result("Features page returns 200", False, error or f"Status: {status}")
    
    # Test demo page
    print(f"{YELLOW}Testing Demo Page...{RESET}")
    success, status, content, error = fetch_url(f'{BASE_URL}/demo')
    results['tests_run'] += 1
    if success and status == 200 and 'demo' in content.lower():
        results['tests_passed'] += 1
        print_result("Demo page returns 200", True)
    else:
        results['tests_failed'] += 1
        print_result("Demo page returns 200", False, error or f"Status: {status}")
    
    # Test about page
    print(f"{YELLOW}Testing About Page...{RESET}")
    success, status, content, error = fetch_url(f'{BASE_URL}/about')
    results['tests_run'] += 1
    if success and status == 200 and 'About' in content:
        results['tests_passed'] += 1
        print_result("About page returns 200", True)
    else:
        results['tests_failed'] += 1
        print_result("About page returns 200", False, error or f"Status: {status}")
    
    # Test CSS
    print(f"{YELLOW}Testing Static CSS...{RESET}")
    success, status, content, error = fetch_url(f'{BASE_URL}/static/css/site.css')
    results['tests_run'] += 1
    if success and status == 200:
        results['tests_passed'] += 1
        print_result("CSS file is accessible", True, f"Size: {len(content)} bytes")
    else:
        results['tests_failed'] += 1
        print_result("CSS file is accessible", False, "CSS not built yet" if not success else error)
    
    # Test JS
    print(f"{YELLOW}Testing Static JavaScript...{RESET}")
    success, status, content, error = fetch_url(f'{BASE_URL}/static/js/main.js')
    results['tests_run'] += 1
    if success and status == 200:
        results['tests_passed'] += 1
        print_result("JavaScript file is accessible", True, f"Size: {len(content)} bytes")
    else:
        results['tests_failed'] += 1
        print_result("JavaScript file is accessible", False, error)
    
    return results

def print_summary(results):
    print(f"\n{BOLD}{'=' * 60}{RESET}")
    print(f"{BOLD}Test Summary{RESET}")
    print(f"{BOLD}{'=' * 60}{RESET}")
    passed = results['tests_passed']
    total = results['tests_run']
    print(f"\n  Tests run:      {total}")
    print(f"  Tests passed:   {GREEN}{passed}{RESET}")
    print(f"  Tests failed:   {RED}{results['tests_failed']}{RESET}")
    if results['tests_failed'] == 0:
        print(f"\n  {GREEN}{BOLD}✓ All tests passed!{RESET}")
        return 0
    else:
        print(f"\n  {RED}{BOLD}✗ Some tests failed.{RESET}")
        print(f"\n  {YELLOW}Troubleshooting:{RESET}")
        print(f"    1. Start Flask server: cd website && python app.py")
        print(f"    2. Build CSS if missing: cd website && npm run build:css\n")
        return 1

def main():
    print(f"{YELLOW}Checking if server is running at {BASE_URL}...{RESET}")
    success, status, content, error = fetch_url(f'{BASE_URL}/health')
    if not success:
        print(f"\n{RED}✗ Cannot connect to server at {BASE_URL}{RESET}")
        print(f"\n{YELLOW}Please start the Flask server first:{RESET}")
        print(f"  cd website")
        print(f"  python app.py")
        print(f"\n{YELLOW}Then run this smoke test in another terminal:{RESET}")
        print(f"  python smoke.py\n")
        sys.exit(1)
    print(f"{GREEN}✓ Server is running{RESET}\n")
    results = run_smoke_tests()
    exit_code = print_summary(results)
    sys.exit(exit_code)

if __name__ == '__main__':
    main()
