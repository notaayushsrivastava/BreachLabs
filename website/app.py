"""BreachLabs Website - Flask Application."""

import os
import sys
from flask import Flask, jsonify, render_template, request
from config import get_template_folder, get_static_folder


def create_app() -> Flask:
    """Create and configure the Flask application."""
    app = Flask(
        __name__,
        template_folder=get_template_folder(),
        static_folder=get_static_folder(),
        static_url_path='/static'
    )
    
    # Configuration
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'breachlabs-dev-key-change-in-production')
    
    # Register routes
    register_routes(app)
    
    return app


def register_routes(app: Flask) -> None:
    """Register all application routes."""
    
    # Make config functions available in templates
    @app.template_global()
    def current_year():
        """Return the current year for footer display."""
        from datetime import datetime
        return datetime.now().year
    
    @app.template_global()
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
    
    @app.route('/')
    def index():
        """Render the home page."""
        return render_template('index.html')
    
    @app.route('/features')
    def features():
        """Render the features page."""
        return render_template('features.html')
    
    @app.route('/about')
    def about():
        """Render the about page."""
        return render_template('about.html')
    
    @app.route('/demo')
    def demo():
        """Render the demo/pipeline visualization page."""
        return render_template('demo.html')
    
    @app.route('/health')
    def healthcheck():
        """Health check endpoint for monitoring."""
        return jsonify({
            'status': 'healthy',
            'service': 'breachlabs-website',
            'version': '1.0.0'
        })
    
    @app.route('/api/health')
    def api_health():
        """API health check endpoint."""
        return jsonify({
            'status': 'healthy',
            'timestamp': __import__('datetime').datetime.utcnow().isoformat()
        })
    
    # Error handlers
    @app.errorhandler(404)
    def not_found(error):
        """Handle 404 errors."""
        return render_template('index.html'), 404  # Redirect to home for now
    
    @app.errorhandler(500)
    def internal_error(error):
        """Handle 500 errors."""
        return jsonify({'error': 'Internal server error'}), 500


app = create_app()


if __name__ == '__main__':
    # Run the development server
    print("=" * 60)
    print("   BreachLabs Website")
    print("   Build. Break. Verify. Fix.")
    print("=" * 60)
    print("   Server running at: http://127.0.0.1:8001")
    print("")
    print("   Pages:")
    print("   - Home: http://127.0.0.1:8001/")
    print("   - Features: http://127.0.0.1:8001/features")
    print("   - Demo: http://127.0.0.1:8001/demo")
    print("   - About: http://127.0.0.1:8001/about")
    print("   - Health: http://127.0.0.1:8001/health")
    print("=" * 60)
    
    app.run(
        host='127.0.0.1',
        port=8001,
        debug=True
    )
