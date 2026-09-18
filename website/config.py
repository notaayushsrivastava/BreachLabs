"""BreachLabs Website Configuration."""

import os
from datetime import datetime
from functools import lru_cache


@lru_cache
def get_project_root() -> str:
    """Get the project root directory (website/)."""
    return os.path.dirname(os.path.abspath(__file__))


@lru_cache
def get_template_folder() -> str:
    """Get the templates directory path."""
    return os.path.join(get_project_root(), 'templates')


@lru_cache
def get_static_folder() -> str:
    """Get the static files directory path."""
    return os.path.join(get_project_root(), 'static')


def current_year() -> int:
    """Return the current year for footer display."""
    return datetime.now().year


def nav_active(current_page: str, target_page: str) -> str:
    """
    Return 'active' class if current page matches target page.
    
    Args:
        current_page: The current page name
        target_page: The page to check against
    
    Returns:
        'active' if pages match, empty string otherwise
    """
    return 'active' if current_page == target_page else ''


def page_title(page_name: str) -> str:
    """Generate page title with site name."""
    return f"{page_name} | BreachLabs" if page_name != "Home" else "BreachLabs - Build. Break. Verify. Fix."
