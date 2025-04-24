from app import app  # noqa: F401
from routes.home import home_bp

# Register blueprints
app.register_blueprint(home_bp)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
