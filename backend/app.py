from flask import Flask, jsonify, request, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import exc 
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, verify_jwt_in_request
from datetime import date, datetime, timedelta
from functools import wraps
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///library.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'
app.config['UPLOAD_FOLDER'] = 'media'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}

CORS(app)

db = SQLAlchemy(app)
jwt = JWTManager(app)

class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    city = db.Column(db.String(100))
    role = db.Column(db.String(20), default='user', nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    profile_photo = db.Column(db.String(300))

    def __repr__(self):
        return f'<User {self.username}>'

class Books(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    author = db.Column(db.String(100), nullable=False)
    published_year = db.Column(db.Integer)
    image_url = db.Column(db.String(300))
    type = db.Column(db.Integer, nullable=False)  # 1, 2, or 3
    available = db.Column(db.Boolean, default=True, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)

    def __repr__(self):
        return f'<Book {self.title}>'


class Loans(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    book_id = db.Column(db.Integer, db.ForeignKey('books.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    loan_date = db.Column(db.Date, default=date.today, nullable=False)
    return_date = db.Column(db.Date)
    late = db.Column(db.Boolean, default=True, nullable=False)

    book = db.relationship('Books', backref=db.backref('loans', lazy=True))
    user = db.relationship('Users', backref=db.backref('loans', lazy=True))

    def __repr__(self):
        return f'<Loan {self.id}>'
    
#Creating media directory..    
if not os.path.exists('media'):
    os.makedirs('media')   
    
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']
    

@app.route('/')
def home():
    return 'Hello, World!'

@app.route('/media/<filename>')
def media(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


#test endpoint
@app.route('/test', methods=['GET'])
def test():
    return jsonify({"message": "This is a test endpoint!"})

# Admin check decorator
def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        verify_jwt_in_request()
        current_user = get_jwt_identity()
        if current_user.get('role') != 'admin':
            return jsonify({"error": "Admin access required"}), 403
        return fn(*args, **kwargs)
    return wrapper


# Register endpoint
@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.form
        username = data.get('username')
        password = data.get('password')
        email = data.get('email')
        city = data.get('city')
        role = data.get('role', 'user')
        
        if 'profile_photo' not in request.files:
            return jsonify({"error": "No profile photo part"}), 400

        file = request.files['profile_photo']

        if file.filename == '':
            return jsonify({"error": "No selected file"}), 400

        if not allowed_file(file.filename):
            return jsonify({"error": "File type not allowed"}), 400

        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        profile_photo_url = f'/media/{filename}'

        if not username or not password or not email:
            return jsonify({"error": "Username, password, and email are required"}), 400

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = Users(username=username, password=hashed_password, email=email, city=city, role=role, profile_photo=profile_photo_url)

        db.session.add(new_user)
        db.session.commit()
        return jsonify({"message": "User registered successfully"}), 201
    except exc.IntegrityError:
        db.session.rollback()
        return jsonify({"error": "Username or email already exists"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Login endpoint
@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return jsonify({"error": "Username and password are required"}), 400

        user = Users.query.filter_by(username=username, is_active=True).first()

        if not user or not check_password_hash(user.password, password):
            return jsonify({"error": "Invalid username or password"}), 401

        access_token = create_access_token(identity={'username': user.username, 'role': user.role})
        return jsonify({"message": "Login successful", "access_token": access_token}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Protected endpoint
@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200

# Admin-only endpoint
@app.route('/admin-only', methods=['GET'])
@admin_required
def admin_only():
    return jsonify({"message": "Welcome, Admin!"}), 200


# Add book endpoint
@app.route('/add-book', methods=['POST'])
@admin_required
def add_book():
    try:
        data = request.form
        title = data.get('title')
        author = data.get('author')
        published_year = data.get('published_year')
        book_type = data.get('type')

        if 'image' not in request.files:
            return jsonify({"error": "No file part"}), 400

        file = request.files['image']

        if file.filename == '':
            return jsonify({"error": "No selected file"}), 400

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            image_url = f'/media/{filename}'

            if not title or not author or not book_type:
                return jsonify({"error": "Title, author, and type are required"}), 400

            new_book = Books(title=title, author=author, published_year=published_year, image_url=image_url, type=book_type)
            db.session.add(new_book)
            db.session.commit()
            return jsonify({"message": "Book added successfully"}), 201
        else:
            return jsonify({"error": "File type not allowed"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Loan book endpoint
@app.route('/loan-book', methods=['POST'])
@jwt_required()
def loan_book():
    try:
        data = request.get_json()
        book_id = data.get('book_id')

        # Get the current user identity
        current_user = get_jwt_identity()
        user_id = Users.query.filter_by(username=current_user['username']).first().id

        # Check if the book exists, is active, and is available
        book = Books.query.filter_by(id=book_id, is_active=True, available=True).first()
        if not book:
            return jsonify({"error": "Book is not available, not active, or does not exist"}), 400

        # Create a new loan entry
        new_loan = Loans(book_id=book_id, user_id=user_id)
        
        # Mark the book as not available
        book.available = False

        db.session.add(new_loan)
        db.session.commit()

        return jsonify({"message": "Book loaned successfully"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    

# Return book endpoint    
@app.route('/return-book', methods=['POST'])
@jwt_required()
def return_book():
    try:
        data = request.get_json()
        book_id = data.get('book_id')

        # Get the current user identity
        current_user = get_jwt_identity()
        user_id = Users.query.filter_by(username=current_user['username']).first().id

        # Check if the loan exists and belongs to the user
        loan = Loans.query.filter_by(book_id=book_id, user_id=user_id, return_date=None).first()
        if not loan:
            return jsonify({"error": "No active loan found for this book and user"}), 400

        # Mark the book as available
        book = Books.query.filter_by(id=book_id).first()
        if book:
            book.available = True

        # Set the return date for the loan
        loan.return_date = date.today()

        db.session.commit()

        return jsonify({"message": "Book returned successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Display all books endpoint
@app.route('/books', methods=['GET'])
def get_books():
    try:
        books = Books.query.filter_by(is_active=True).all()
        result = [
            {
                'id': book.id,
                'title': book.title,
                'author': book.author,
                'published_year': book.published_year,
                'image_url': book.image_url,
                'type': book.type,
                'available': book.available,
            } for book in books
        ]
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
  
# Display all users endpoint
@app.route('/users', methods=['GET'])
@jwt_required()
def get_users():
    try:
        current_user = get_jwt_identity()
        users = Users.query.filter_by(is_active=True).all()
        if current_user['role'] == 'admin':
            result = [
                {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'city': user.city,
                    'role': user.role,
                    'profile_photo': user.profile_photo
                } for user in users
            ]
        else:
            result = [
                {
                    'username': user.username,
                    'city': user.city,
                    'profile_photo': user.profile_photo
                } for user in users
            ]
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/my-profile', methods=['GET'])
@jwt_required()
def my_profile():
    try:
        current_user = get_jwt_identity()
        user = Users.query.filter_by(username=current_user['username']).first()
        if not user:
            return jsonify({"error": "User not found"}), 404

        result = {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'city': user.city,
            'role': user.role,
            'is_active': user.is_active,
            'profile_photo': user.profile_photo
        }
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    

@app.route('/loans', methods=['GET'])
@jwt_required()
def get_loans():
    try:
        current_user = get_jwt_identity()
        user = Users.query.filter_by(username=current_user['username']).first()

        if user.role == 'admin':
            # For admin, fetch all loans
            loans = Loans.query.all()
        else:
            # For regular users, fetch only their own loans
            loans = Loans.query.filter_by(user_id=user.id).all()

        result = []
        for loan in loans:
            loan_data = {
                'user': {
                    'username': loan.user.username,
                    'profile_photo': loan.user.profile_photo
                },
                'book': {
                    'title': loan.book.title,
                    'image_url': loan.book.image_url
                },
                'loan_date': loan.loan_date.isoformat(),
                'return_date': loan.return_date.isoformat() if loan.return_date else None
            }
            result.append(loan_data)

        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/late-loans', methods=['GET'])
@jwt_required()
def get_late_loans():
    try:
        current_user = get_jwt_identity()
        user = Users.query.filter_by(username=current_user['username']).first()

        today = datetime.now().date()

        if user.role == 'admin':
            # For admin, fetch all late loans
            loans = Loans.query.filter(Loans.return_date == None).all()
        else:
            # For regular users, fetch only their own late loans
            loans = Loans.query.filter_by(user_id=user.id, return_date=None).all()

        result = []
        for loan in loans:
            book = loan.book
            loan_duration = (today - loan.loan_date).days

            # Determine if the loan is late based on book type
            is_late = False
            if book.type == 1 and loan_duration > 10:
                is_late = True
            elif book.type == 2 and loan_duration > 5:
                is_late = True
            elif book.type == 3 and loan_duration > 2:
                is_late = True

            if is_late:
                loan_data = {
                    'user': {
                        'username': loan.user.username,
                        'profile_photo': loan.user.profile_photo
                    },
                    'book': {
                        'title': book.title,
                        'image_url': book.image_url,
                        'type': book.type
                    },
                    'loan_date': loan.loan_date.isoformat(),
                    'days_overdue': loan_duration - (10 if book.type == 1 else 5 if book.type == 2 else 2)
                }
                result.append(loan_data)

        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500   


@app.route('/remove-book/<int:book_id>', methods=['PUT'])
@admin_required
def remove_book(book_id):
    try:
        book = Books.query.get(book_id)

        if not book:
            return jsonify({"error": "Book not found"}), 404

        if not book.available:
            return jsonify({"error": "Cannot remove book. It is currently on loan and must be returned first."}), 400

        book.is_active = False
        db.session.commit()

        return jsonify({"message": "Book removed successfully"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500


@app.route('/remove-user/<int:user_id>', methods=['PUT'])
@admin_required
def remove_user(user_id):
    try:
        user = Users.query.get(user_id)

        if not user:
            return jsonify({"error": "User not found"}), 404

        # Check if the user has any active loans
        active_loans = Loans.query.filter_by(user_id=user_id, return_date=None).first()
        if active_loans:
            return jsonify({"error": "Cannot remove user. They have active loans. All books must be returned first."}), 400

        user.is_active = False
        db.session.commit()

        return jsonify({"message": "User removed successfully"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500     


@app.route('/find-book', methods=['GET'])
def find_book():
    try:
        book_name = request.args.get('name')
        if not book_name:
            return jsonify({"error": "Book name parameter is required"}), 400

        books = Books.query.filter(Books.title.ilike(f"%{book_name}%"), Books.is_active==True).all()
        
        result = [
            {
                'id': book.id,
                'title': book.title,
                'author': book.author,
                'published_year': book.published_year,
                'image_url': book.image_url,
                'type': book.type,
                'available': book.available,
            } for book in books
        ]
        
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/find-user', methods=['GET'])
@jwt_required()
def find_user():
    try:
        current_user = get_jwt_identity()
        user_name = request.args.get('name')
        if not user_name:
            return jsonify({"error": "User name parameter is required"}), 400

        users = Users.query.filter(Users.username.ilike(f"%{user_name}%"), Users.is_active==True).all()
        
        if current_user['role'] == 'admin':
            result = [
                {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'city': user.city,
                    'role': user.role,
                    'profile_photo': user.profile_photo
                } for user in users
            ]
        else:
            result = [
                {
                    'username': user.username,
                    'city': user.city,
                    'profile_photo': user.profile_photo
                } for user in users
            ]
        
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/activate/<string:type>/<int:item_id>', methods=['PUT'])
@admin_required
def activate_item(type, item_id):
    try:
        if type not in ['user', 'book']:
            return jsonify({"error": "Invalid type. Must be 'user' or 'book'"}), 400

        if type == 'user':
            item = Users.query.get(item_id)
            item_type = "User"
        else:  # type == 'book'
            item = Books.query.get(item_id)
            item_type = "Book"

        if not item:
            return jsonify({"error": f"{item_type} not found"}), 404

        if item.is_active:
            return jsonify({"message": f"{item_type} is already active"}), 400

        item.is_active = True
        db.session.commit()

        response = {
            "message": f"{item_type} activated successfully",
            type: {
                "id": item.id,
                "is_active": item.is_active
            }
        }

        if type == 'user':
            response[type].update({
                "username": item.username,
                "email": item.email
            })
        else:  # type == 'book'
            response[type].update({
                "title": item.title,
                "author": item.author
            })

        return jsonify(response), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500
    

@app.route('/update-book/<int:book_id>', methods=['PUT'])
@admin_required
def update_book(book_id):
    try:
        book = Books.query.get(book_id)
        if not book:
            return jsonify({"error": "Book not found"}), 404

        data = request.form

        # Update book fields if provided in the request
        if 'title' in data:
            book.title = data['title']
        if 'author' in data:
            book.author = data['author']
        if 'published_year' in data:
            book.published_year = data['published_year']
        if 'type' in data:
            book.type = data['type']
        if 'available' in data:
            book.available = data['available'].lower() == 'true'

        # Handle image update
        if 'image' in request.files:
            file = request.files['image']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                book.image_url = f'/media/{filename}'

        db.session.commit()

        return jsonify({
            "message": "Book updated successfully",
            "book": {
                "id": book.id,
                "title": book.title,
                "author": book.author,
                "published_year": book.published_year,
                "image_url": book.image_url,
                "type": book.type,
                "available": book.available
            }
        }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

@app.route('/update-user/<int:user_id>', methods=['PUT'])
@admin_required
def update_user(user_id):
    try:
        user = Users.query.get(user_id)
        if not user:
            return jsonify({"error": "User not found"}), 404

        data = request.form

        # Update user fields if provided in the request
        if 'username' in data:
            user.username = data['username']
        if 'email' in data:
            user.email = data['email']
        if 'city' in data:
            user.city = data['city']
        if 'role' in data:
            user.role = data['role']
        if 'is_active' in data:
            user.is_active = data['is_active'].lower() == 'true'
        if 'password' in data:
            user.password = generate_password_hash(data['password'], method='pbkdf2:sha256')

        # Handle profile photo update
        if 'profile_photo' in request.files:
            file = request.files['profile_photo']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                user.profile_photo = f'/media/{filename}'

        db.session.commit()

        return jsonify({
            "message": "User updated successfully",
            "user": {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "city": user.city,
                "role": user.role,
                "is_active": user.is_active,
                "profile_photo": user.profile_photo
            }
        }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    with app.app_context():
        db.create_all()    
    app.run(debug=True)