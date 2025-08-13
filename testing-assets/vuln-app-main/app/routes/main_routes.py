import sys
from flask import Blueprint, render_template, request, redirect, url_for, flash, send_from_directory, current_app, abort, send_file
from app import db
from app.models import Document, Comment, User
from flask_login import login_required, current_user
import os
from werkzeug.utils import secure_filename

# Create main blueprint
main = Blueprint('main', __name__)

@main.route('/')
def index():
    # SQL Injection vulnerability in search
    search_query = request.args.get('q', '')
    if search_query:
        # Vulnerable to SQL Injection
        query = f"SELECT * FROM document WHERE title LIKE '%{search_query}%'"
        documents = db.session.execute(query).fetchall()
    else:
        documents = Document.query.all()
    return render_template('index.html', documents=documents)

@main.route('/document/<int:doc_id>')
def view_document(doc_id):
    # IDOR vulnerability - no check if user has access to this document
    document = Document.query.get_or_404(doc_id)
    return render_template('document.html', document=document)

@main.route('/profile/<int:user_id>')
def view_profile(user_id):
    # IDOR Vulnerability: No se verifica si el usuario actual tiene permiso para ver este perfil
    user = User.query.get_or_404(user_id)
    
    # Mostrar información sensible del usuario
    user_documents = Document.query.filter_by(user_id=user_id).all()
    
    # Información sensible que no debería ser accesible sin autorización
    user_info = {
        'username': user.username,
        'email': user.email,
        'is_admin': user.is_admin,
        'document_count': len(user_documents),
        'documents': [doc.title for doc in user_documents]
    }
    
    return render_template('profile.html', user=user, user_info=user_info)

@main.route('/document/upload', methods=['POST'])
@login_required
def upload_document():
    if 'file' not in request.files:
        return 'No file part', 400
    
    file = request.files['file']
    if file.filename == '':
        return 'No selected file', 400
    
    # Path Traversal vulnerability - intentionally vulnerable
    # Using the raw filename without any sanitization
    filename = file.filename
    
    # Make sure uploads directory exists
    upload_dir = os.path.join(current_app.root_path, 'uploads')
    if not os.path.exists(upload_dir):
        os.makedirs(upload_dir, exist_ok=True)
    
    # Create the full path - vulnerable to path traversal
    file_path = os.path.abspath(os.path.join(upload_dir, filename))
    
    # Ensure we're still within the uploads directory (but this check can be bypassed with path traversal)
    if not file_path.startswith(os.path.abspath(upload_dir) + os.sep):
        return 'Invalid file path', 400
    
    # Save the file
    file.save(file_path)
    
    # Store the relative path in the database
    relative_path = os.path.relpath(file_path, os.path.abspath(upload_dir))
    
    new_doc = Document(
        title=request.form.get('title', 'Untitled'),
        content=request.form.get('content', ''),
        file_path=relative_path,  # Store relative path to make downloads work
        user_id=current_user.id
    )
    db.session.add(new_doc)
    db.session.commit()
    
    return redirect(url_for('main.view_document', doc_id=new_doc.id))

@main.route('/download', defaults={'filename': None})
@main.route('/download/<path:filename>')
def download_file(filename):
    # Get filename from query parameter if not in path
    if filename is None:
        filename = request.args.get('file')
        if not filename:
            abort(400, "File parameter is required")
    
    # Debug output
    print(f"Attempting to access file: {filename}", file=sys.stderr)
    
    # Path Traversal vulnerability - intentionally vulnerable
    base_dir = os.path.abspath('/')  # Start from root directory
    file_path = os.path.abspath(os.path.join(base_dir, filename.lstrip('/')))
    
    # Debug output
    print(f"Full file path: {file_path}", file=sys.stderr)
    
    # Check if file exists and is a file (but don't check the path!)
    if not os.path.isfile(file_path):
        print(f"File not found: {file_path}", file=sys.stderr)
        abort(404)
    
    # Send the file - this is where the path traversal happens
    return send_file(
        file_path,
        as_attachment=True
    )

@main.route('/comment', methods=['POST'])
@login_required
def add_comment():
    document_id = request.form.get('document_id')
    content = request.form.get('content')
    
    # Stored XSS vulnerability - user input is not sanitized
    new_comment = Comment(
        content=content,
        user_id=current_user.id,
        document_id=document_id
    )
    db.session.add(new_comment)
    db.session.commit()
    
    return redirect(url_for('main.view_document', doc_id=document_id))
