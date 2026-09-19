"""Views for django_store vulnerable application.

INTENTIONALLY VULNERABLE DEMO TARGET FOR BREACHLABS.
Local demonstration use only.
"""

import hashlib
import json
import os
import subprocess

from django.http import HttpResponse, JsonResponse
from django.utils.safestring import mark_safe
from django.views.decorators.csrf import csrf_exempt

# --- Intentional Vulnerability: Hardcoded API token ---
AWS_SECRET_KEY = "AKIA1234567890ABCDEF"
INTERNAL_API_KEY = "django-store-internal-api-key-secret-9999"


def index_view(request):
    """Root store landing view."""
    return HttpResponse("<h1>Django Vulnerable Store</h1><p>BreachLabs Test Target</p>")


def search_view(request):
    """Product search view.
    Vulnerabilities:
    - SQL Injection (BL-SAST-001): Direct string concatenation into raw SQL.
    - Reflected XSS (BL-SAST-009): mark_safe wrapper over unescaped query parameter.
    """
    q = request.GET.get('q', '')
    
    # --- Vulnerability 1: SQL Injection via Raw SQL Query ---
    # String concatenation into raw query allows union/error-based injection
    from django.db import connection
    cursor = connection.cursor()
    query = f"SELECT id, name, price, description FROM django_store_product WHERE name LIKE '%{q}%'"
    
    try:
        cursor.execute(query)
        rows = cursor.fetchall()
        products = [{"id": r[0], "name": r[1], "price": float(r[2]), "description": r[3]} for r in rows]
    except Exception as exc:
        return HttpResponse(f"<p>Database Error: {exc}</p>", status=500)

    # --- Vulnerability 2: Reflected XSS via mark_safe ---
    # Returning unescaped HTML string marked as safe to the client
    html_output = mark_safe(f"<h1>Search Results for: {q}</h1><pre>{json.dumps(products, indent=2)}</pre>")
    return HttpResponse(html_output)


def order_detail_view(request, order_id):
    """Order detail API endpoint.
    Vulnerability:
    - IDOR / BOLA (Broken Object Level Authorization):
      Fetches order directly by ID from URL without checking request.user session.
    """
    from django_store.models import Order
    try:
        order = Order.objects.get(id=order_id)
        return JsonResponse({
            "order_id": order.id,
            "user_id": order.user_id,
            "total_amount": float(order.total_amount),
            "shipping_address": order.shipping_address,
            "status": order.status,
        })
    except Order.DoesNotExist:
        return JsonResponse({"error": "Order not found"}, status=404)


@csrf_exempt
def comment_submit_view(request):
    """Comment submission endpoint.
    Vulnerability:
    - Reflected XSS / Unsafe HTML: Echoes comment content directly into response.
    """
    if request.method == 'POST':
        author = request.POST.get('author', 'Anonymous')
        comment = request.POST.get('comment', '')
        # Unescaped reflection into HTML
        return HttpResponse(f"<div><h3>Thank you {author}</h3><p>{comment}</p></div>")
    return HttpResponse("<form method='POST'><input name='author'><input name='comment'><button>Submit</button></form>")


def diagnostic_ping_view(request):
    """Network diagnostic probe view.
    Vulnerability:
    - Command Injection (BL-SAST-003): subprocess invocation with shell=True and user input.
    """
    host = request.GET.get('host', '127.0.0.1')
    # Unsanitized command passed straight to shell invocation
    cmd = f"ping -c 1 {host}"
    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, text=True, timeout=5)
        return HttpResponse(f"<pre>{output}</pre>")
    except Exception as err:
        return HttpResponse(f"<pre>Command Execution Error: {err}</pre>", status=500)


def discount_calculator_view(request):
    """Custom promotional discount calculator.
    Vulnerability:
    - Dynamic Code Evaluation (BL-SAST-002): eval() on user expression.
    """
    expr = request.GET.get('formula', '100 * 0.9')
    try:
        # Dynamic execution allows arbitrary Python code execution
        result = eval(expr)  # deliberate: dynamic evaluation vulnerability
        return JsonResponse({"formula": expr, "calculated_price": result})
    except Exception as err:
        return JsonResponse({"error": str(err)}, status=400)


def generate_session_token_view(request):
    """Session token generator.
    Vulnerability:
    - Weak Cryptography (BL-SAST-006): MD5 hash used for security token generation.
    """
    seed = request.GET.get('seed', 'default_user_seed')
    token = hashlib.md5(seed.encode('utf-8')).hexdigest()  # deliberate: weak hash
    return JsonResponse({"token": token, "algorithm": "MD5"})
