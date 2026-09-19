#!/usr/bin/env python
"""Django's command-line utility for administrative tasks."""
import os
import sys

def main():
    """Run administrative tasks or standalone demo server."""
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'django_store.settings')
    try:
        from django.core.management import execute_from_command_line
        execute_from_command_line(sys.argv)
    except ImportError:
        # Fallback to pure-Python WSGI server
        port = int(os.environ.get("PORT", "5000"))
        host = os.environ.get("HOST", "127.0.0.1")
        for arg in sys.argv:
            if ":" in arg:
                parts = arg.split(":")
                if len(parts) == 2 and parts[1].isdigit():
                    host = parts[0] or host
                    port = int(parts[1])
            elif arg.isdigit():
                port = int(arg)
        from django_store.django_shim import run_standalone_django_server
        run_standalone_django_server(host, port)


if __name__ == '__main__':
    main()
