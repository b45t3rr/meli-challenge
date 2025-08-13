from app import create_app, db
from app.models import User, Document, Comment
import os

app = create_app()

# Create uploads directory if it doesn't exist
if not os.path.exists('uploads'):
    os.makedirs('uploads')

# Create database tables and admin user
def init_db():
    with app.app_context():
        # Create tables if they don't exist
        db.create_all()
        
        # Create admin user if it doesn't exist
        if not User.query.filter_by(username='admin').first():
            admin = User(
                username='admin',
                email='admin@example.com',
                is_admin=True
            )
            admin.set_password('admin123')
            db.session.add(admin)
            
            # Create some sample data
            user1 = User(
                username='user1',
                email='user1@example.com'
            )
            user1.set_password('user123')
            db.session.add(user1)
            
            db.session.commit()
            
            # Create a document after users are created
            doc1 = Document(
                title='Secret Document',
                content='This is a secret document with sensitive information.',
                user_id=admin.id
            )
            db.session.add(doc1)
            
            db.session.commit()

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=True)
