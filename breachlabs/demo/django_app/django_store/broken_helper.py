"""Helper utilities for django_store with intentional syntax/diagnostic glitches."""

# --- Intentional Syntax / Runtime Flaw for Error Diagnosis Testing ---
def calculate_vat_tax(amount)
    # Missing colon syntax error
    rate = 0.20
    return amount * rate
