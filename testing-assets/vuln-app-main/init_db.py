from app import create_app, db
from app.models import User, Document, Comment

def init_db():
    app = create_app()
    
    with app.app_context():
        # Create all database tables
        db.create_all()
        
        # Create admin user if it doesn't exist
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(
                username='admin',
                email='admin@example.com',
                is_admin=True
            )
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
            print("Created admin user")
        
        # Create regular user if it doesn't exist
        user1 = User.query.filter_by(username='user1').first()
        if not user1:
            user1 = User(
                username='user1',
                email='user1@example.com'
            )
            user1.set_password('user123')
            db.session.add(user1)
            db.session.commit()
            print("Created regular user")
        
        # Create a sample document if none exist
        if Document.query.count() == 0:
            doc = Document(
                title='Welcome to the Vulnerable App',
                content='This is a sample document with sensitive information.',
                user_id=admin.id
            )
            db.session.add(doc)
            db.session.commit()
            
            # Add a sample comment
            comment = Comment(
                content='This is a test comment with <strong>HTML</strong> and <script>alert("XSS")</script>',
                user_id=user1.id,
                document_id=doc.id
            )
            db.session.add(comment)
            db.session.commit()
            print("Created sample document and comment")
        
        print("Database initialization complete!")

if __name__ == '__main__':
    init_db()
