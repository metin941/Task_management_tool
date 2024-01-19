from app import app, db

with app.app_context():
    # Drop all tables in the database
    db.drop_all()

    # Create the tables again
    db.create_all()