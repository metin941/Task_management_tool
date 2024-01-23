import tkinter as tk
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from tkinter import messagebox

def reset_database():
    # Import your Flask app and db instance from app
    from app import app, db

    with app.app_context():
        # Drop all tables in the database
        db.drop_all()

        # Create the tables again
        db.create_all()

        tk.messagebox.showinfo("Success", "Database tables reset successfully")

# Create a Tkinter window
window = tk.Tk()
window.title("Database Delete/Reset")
window.geometry("300x300")

# Create and place widgets in the window
reset_button = tk.Button(window, text="Reset Database", command=reset_database)
reset_button.pack()

# Start the Tkinter event loop
window.mainloop()
