import json
import os
import secrets
import subprocess
from datetime import timedelta

from flask import Flask, render_template, request, redirect, jsonify, make_response, session, flash, url_for, abort
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

from flask_session import Session
from flask_jwt_extended import JWTManager, create_access_token
from OpenSSL import SSL
from flask_bcrypt import Bcrypt
import bleach

import csv

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = 'dannydev1to'
app.config['JWT_SECRET_KEY'] = 'your-secret-key'  # Change this to a secure secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mydatabase.db'
UPCITEMDB_API_URL = "https://api.upcitemdb.com/prod/trial/lookup"  # API URL for UPC lookup (Trial {<100 requests per day})
product_list = []
db = SQLAlchemy(app)
migrate = Migrate(app, db)  # Initialize Flask-Migrate

ALLOWED_TAGS = ['a', 'abbr', 'acronym', 'b', 'blockquote', 'code', 'em', 'i', 'li', 'ol', 'strong', 'ul']
ALLOWED_ATTRIBUTES = {'a': ['href', 'title'], 'abbr': ['title'], 'acronym': ['title']}

available_liquor_types = []
available_mixer_types = []
glass_options = []
available_recipes = []
selected_items = []  # To temporarily store selected items

# Specify the paths to your SSL certificate and key files within the 'instance' folder
#cert_file = os.path.join(app.root_path, 'instance', 'ssl', 'cert.pem')
#key_file = os.path.join(app.root_path, 'instance', 'ssl', 'key.pem')


# Function to check if SSL files exist, and generate them if not
#def ensure_ssl_files():
#    if not os.path.exists(cert_file) or not os.path.exists(key_file):
#        print("SSL certificate and key files not found. Generating them...")
#        generate_ssl_files()
#        print("SSL certificate and key files generated.")


# Function to generate SSL certificate and key files
#def generate_ssl_files():
    # Create the 'ssl' directory if it doesn't exist
#    ssl_dir = os.path.dirname(cert_file)
#    os.makedirs(ssl_dir, exist_ok=True)

    # Generate the SSL certificate and key
#    subprocess.run(
#        ['openssl', 'req', '-x509', '-newkey', 'rsa:4096', '-keyout', key_file, '-out', cert_file, '-days', '3650'])


# Ensure SSL files before creating the SSL context
#ensure_ssl_files()

# Create an SSL context
#context = SSL.Context(SSL.SSLv23_METHOD)
#context.use_privatekey_file(key_file)
#context.use_certificate_file(cert_file)

# Initialize Flask-Session and JWTManager
#app.config['SESSION_TYPE'] = 'filesystem'  # You can change this as needed
#app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=30)  # Set token expiration to 30 days
#app.config['SESSION_PERMANENT'] = False  # Session doesn't expire on browser close

Session(app)
jwt = JWTManager(app)


# Utility function to sanitize user input
def sanitize_input(input_text):
    return bleach.clean(input_text, tags=ALLOWED_TAGS, attributes=ALLOWED_ATTRIBUTES)


# Utility function to normalize a username to lowercase
def normalize(username):
    return username.lower()


def read_glass_options():
    glass_file_path = os.path.join(app.root_path, 'instance', 'glasses.txt')  # Adjust the path as needed
    try:
        with open(glass_file_path, 'r') as file:
            glass_options.extend(line.strip() for line in file if line.strip())

    except FileNotFoundError:
        print("File 'glasses.txt' not found. Please make sure the file exists.")


# Call the function to read glass options
read_glass_options()


def get_color_scheme(selected_scheme):
    # Define color schemes for different options
    color_schemes = {
        'Default': {
            'primary_color': '#FF5733',
            'secondary_color': '#0099CC',

            'background_color': '#f8e4c9',
            'dark': 'false',
            # Add more colors as needed
        },
        'Dark Mode': {
            'primary_color': '#FFFFFF',
            'secondary_color': '#00FFFF',
            'background_color': '#333333',
            'dark': 'true',

        },
        'Red': {
            'primary_color': '#FFFFFF',
            'secondary_color': '#00FFFF',
            'background_color': '#f6483f',
            'dark': 'false',

        },
        'Default 2': {
            'primary_color': '#FFFDE7',
            'secondary_color': '#795548',
            'background_color': '#F5F5DC',
            'color_4': '#000000',
            'color_5': '#FFD700',
            'dark': 'false',

        },
        'Dark Mode 2': {
            'primary_color': '#332929',
            'secondary_color': '#FFD700',
            'background_color': '#000000',
            'color_4': '#B87333',
            'color_5': '#8B0000',
            'dark': 'true',

        },
        'Sepia': {
            'primary_color': '#5d5d5d',
            'secondary_color': '#353535',
            'background_color': '#EED9C2',
            'color_4': '#D9C2AA',
            'color_5': '#C2AB92',
            'dark': 'false',

        },
        'Newspaper': {
            'primary_color': '#5d5d5d',
            'secondary_color': '#353535',
            'background_color': '#dfdfdf',
            'color_4': '#000000',
            'color_5': '#E0E0E0',
            'dark': 'false',

        },
        'Neon': {
            'primary_color': '#FF0000',
            'secondary_color': '#00FF00',
            'background_color': '#0000FF',
            'color_4': '#FFFF00',
            'color_5': '#FF00FF',
            'dark': 'false',

        },
    }

    # Get the selected color scheme or default to 'default'
    selected_color_scheme = color_schemes.get(selected_scheme, color_schemes['Default'])

    return selected_color_scheme


def get_saved_recipes_from_cookies():
    saved_recipes_cookie = sanitize_input(request.cookies.get('saved-recipes-list'))
    if saved_recipes_cookie:
        cleaned_saved_recipes_list = saved_recipes_cookie.strip("[]").split(',')
        return [recipe.strip('"') for recipe in cleaned_saved_recipes_list]
    return []


def is_user_admin(user_id):
    if user_id:
        user = User.query.get(user_id)
        if user and user.is_admin:
            return True
    return False


def add_missing_default_liquors():
    with app.app_context():
        print("Add Missing Default Liquors")
        csv_file_path = os.path.join(app.root_path, 'instance', 'default_liquor.csv')

        with open(csv_file_path, 'r', newline='') as csvfile:
            liquor_reader = csv.DictReader(csvfile)
            for row in liquor_reader:
                liquor_name = row['name']
                liquor_type = row['type']
                abv = row.get('abv', None)

                existing_liquor = DefaultLiquor.query.filter_by(name=liquor_name, type=liquor_type, abv=abv).first()
                if not existing_liquor:
                    new_default_liquor = DefaultLiquor(name=liquor_name, type=liquor_type, abv=abv)
                    db.session.add(new_default_liquor)

        db.session.commit()


@app.route('/get-liquor-list')
def get_liquor_list():
    available_liquors = []

    # Retrieve default liquors from the DefaultLiquor table
    default_liquors = DefaultLiquor.query.all()
    for default_liquor in default_liquors:
        available_liquors.append({
            'name': default_liquor.name,
            'type': default_liquor.type,
            'abv': default_liquor.abv,
            'custom': False  # Indicate that it's not a custom liquor
        })

    # Retrieve custom liquors with the custom flag set to true
    custom_liquors = Liquor.query.filter_by(custom=True).all()
    for custom_liquor in custom_liquors:
        available_liquors.append({
            'name': custom_liquor.name,
            'type': custom_liquor.type,
            'abv': custom_liquor.abv,
            'custom': True  # Indicate that it's a custom liquor
        })

    return available_liquors


@app.route('/get-mixer-list')
def get_mixer_list():
    available_mixers = []

    # Construct the path to the default_mixers.csv file in the instance folder
    csv_file_path = os.path.join(app.root_path, 'instance', 'default_mixers.csv')

    with open(csv_file_path, 'r', newline='') as csvfile:
        mixer_reader = csv.DictReader(csvfile)
        for row in mixer_reader:
            mixer_name = row['name']
            mixer_type = row['type']

            existing_mixer = Mixer.query.filter_by(name=mixer_name, type=mixer_type).first()
            if not existing_mixer:
                available_mixers.append(row)

    # Retrieve custom mixers with the custom flag set to true
    custom_mixers = Mixer.query.filter_by(custom=True).all()
    for custom_mixer in custom_mixers:
        available_mixers.append({
            'name': custom_mixer.name,
            'type': custom_mixer.type,
            'custom': True  # Indicate that it's a custom mixer
        })

    return available_mixers


@app.route('/get-garnish-list')
def get_garnish_list():
    available_garnishes = []

    # Construct the path to the default_garnish.csv file in the instance folder
    csv_file_path = os.path.join(app.root_path, 'instance', 'default_garnishes.csv')

    with open(csv_file_path, 'r', newline='') as csvfile:
        garnish_reader = csv.DictReader(csvfile)
        for row in garnish_reader:
            garnish_name = row['name']
            garnish_type = row['type']

            existing_garnish = Garnish.query.filter_by(name=garnish_name, type=garnish_type).first()
            if not existing_garnish:
                available_garnishes.append(row)

    # Retrieve custom garnishes with the custom flag set to true
    custom_garnishes = Garnish.query.filter_by(custom=True).all()
    for custom_garnish in custom_garnishes:
        available_garnishes.append({
            'name': custom_garnish.name,
            'type': custom_garnish.type,
            'custom': True  # Indicate that it's a custom garnish
        })

    return available_garnishes


class Liquor(db.Model):
    __tablename__ = 'liquor'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    abv = db.Column(db.String(10), nullable=True, default=None)
    type = db.Column(db.String(50), nullable=False)
    custom = db.Column(db.Boolean, default=False, nullable=False)

    def __init__(self, name, type, abv=None, custom=False):  # Make abv parameter optional
        self.name = name
        self.abv = abv
        self.type = type
        self.custom = custom


class DefaultLiquor(db.Model):
    __tablename__ = 'default_liquor'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    abv = db.Column(db.String(10), nullable=True, default=None)
    type = db.Column(db.String(50), nullable=False)

    def __init__(self, name, type, abv=None):  # Make abv parameter optional
        self.name = name
        self.abv = abv
        self.type = type


class LiquorType(db.Model):
    __tablename__ = 'liquor_types'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    color = db.Column(db.String(7))  # Store color as a hex string (e.g., "#RRGGBB")


class User(db.Model):
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(256), nullable=False)
    firstName = db.Column(db.String(120))
    is_admin = db.Column(db.Boolean, default=False)  # Add a new column for admin status

    def __init__(self, username, password, firstName):
        self.username = username
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')
        self.firstName = firstName
        self.is_admin = False


class Mixer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    type = db.Column(db.String(50), nullable=False)
    custom = db.Column(db.Boolean, default=False, nullable=False)

    def __init__(self, name, type, custom=False):  # Make abv parameter optional
        self.name = name
        self.type = type
        self.custom = custom


class Garnish(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    type = db.Column(db.String(50), nullable=False)
    custom = db.Column(db.Boolean, default=False, nullable=False)

    def __init__(self, name, type, custom=False):  # Make abv parameter optional
        self.name = name
        self.type = type
        self.custom = custom


class Recipe(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(100), nullable=True)
    portions = db.Column(db.String(50), nullable=False)
    instructions = db.Column(db.Text, nullable=False)
    glass = db.Column(db.String(50), nullable=False)
    custom = db.Column(db.Boolean, default=False, nullable=False)
    ingredients = db.relationship('Ingredient', backref='recipe', lazy=True)
    liquors = db.relationship('Liquor', secondary='recipe_liquor', backref='recipes')
    ingredient_types = db.Column(db.String(500))  # New column to store ingredient types
    rating = db.Column(db.Float, nullable=True)

    def add_ingredient_type(self, ingredient_type):
        if not self.ingredient_types:
            self.ingredient_types = ingredient_type
        else:
            self.ingredient_types += f', {ingredient_type}'


class RecipeLiquor(db.Model):
    __tablename__ = 'recipe_liquor'

    recipe_id = db.Column(db.Integer, db.ForeignKey('recipe.id'), primary_key=True)
    liquor_id = db.Column(db.Integer, db.ForeignKey('liquor.id'), primary_key=True)


class Ingredient(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    recipe_id = db.Column(db.Integer, db.ForeignKey('recipe.id'), nullable=False)
    type = db.Column(db.String(255))  # Add a 'type' field for ingredient type (e.g., "Liquor," "Mixer," "Garnish")
    category = db.Column(db.String(50))  # Add a 'category' field for ingredient category
    quantity = db.Column(db.Float, nullable=True)  # Add a 'quantity' field for ingredient quantity
    unit = db.Column(db.String(20), nullable=True)  # Add a 'unit' field for ingredient unit (e.g., "ml", "oz")


with app.app_context():
    db.create_all()

    csv_file_path = os.path.join(app.root_path, 'instance', 'default_recipes.csv')
    with open(csv_file_path, 'r', newline='') as csvfile:
        recipe_reader = csv.DictReader(csvfile)
        for row in recipe_reader:
            # print(row)
            name = row['name']
            description = row.get('description', None)
            portions = row['portions']
            instructions = row['instructions']
            glass = row['glass']
            custom = row['custom'] == 'TRUE'
            ingredient_quantities = row['ingredient quantities'].split('\n')
            ingredients = row['ingredients'].split('\n')
            # print("Ingredient Quantities:", ingredient_quantities)
            # print("Ingredients List:", ingredients)
            existing_recipe = Recipe.query.filter_by(name=name).first()
            if not existing_recipe:
                recipe_description = description
                new_recipe = Recipe(name=name, description=recipe_description, portions=portions,
                                    instructions=instructions,
                                    glass=glass, custom=custom)
                db.session.add(new_recipe)
                db.session.commit()

                for quantity, ingredient_name in zip(ingredient_quantities, ingredients):
                    if quantity == '-':
                        ingredient_entry = ingredient_name.capitalize()  # Capitalize the ingredient
                    else:
                        ingredient_entry = quantity + ' ' + ingredient_name.capitalize()  # Capitalize both parts
                    ingredient = Ingredient(name=ingredient_entry.strip())  # Strip whitespace
                    new_recipe.ingredients.append(ingredient)
                    db.session.add(ingredient)
                    db.session.commit()

    # Check available_recipes and add custom recipes if not already present
    for recipe_data in available_recipes:
        recipe_name = recipe_data['name']
        existing_recipe = Recipe.query.filter_by(name=recipe_name).first()

        if not existing_recipe:
            new_recipe = Recipe(
                name=recipe_name,
                portions=recipe_data['details']['portions'],
                instructions=recipe_data['details']['instructions'],
                glass=recipe_data['details']['glass'],
                custom=True
            )

            for ingredient_name in recipe_data['details']['ingredients']:
                ingredient = Ingredient(name=ingredient_name)
                new_recipe.ingredients.append(ingredient)

            db.session.add(new_recipe)
            db.session.commit()


def populate_liquor_types():
    print("Populate Liquor Types")
    with app.app_context():
        liquors = DefaultLiquor.query.all()

        for liquor in liquors:
            existing_liquor_type = LiquorType.query.filter_by(name=liquor.type).first()
            if not existing_liquor_type:
                random_hex_code = secrets.token_hex(3)  # You can adjust the length as needed
                new_type = LiquorType(name=liquor.type, color=random_hex_code)
                db.session.add(new_type)
                db.session.commit()


add_missing_default_liquors()
populate_liquor_types()


# Define the hoverBackgroundColor function
def hoverBackgroundColor(secondary_color):
    # Convert the secondary color to RGB values
    rgb_values = secondary_color.lstrip('#')
    r, g, b = tuple(int(rgb_values[i:i + 2], 16) for i in (0, 2, 4))

    # Calculate the lowered RGB values
    lowered_r = max(r - 20, 0)
    lowered_g = max(g - 20, 0)
    lowered_b = max(b - 20, 0)

    # Format the lowered color as a hexadecimal string
    lowered_secondary_color = "#{:02x}{:02x}{:02x}".format(lowered_r, lowered_g, lowered_b)

    return lowered_secondary_color


# Function to print user accounts
def print_user_accounts():
    users = User.query.all()
    print("User Accounts:")
    for user in users:
        print(f"ID: {user.id}, Username: {user.username}")


def generate_access_token(user_id):
    # Create an access token with the user's ID as payload
    access_token = create_access_token(identity=user_id)
    return access_token


@app.route('/create-account')
def create_account():
    # Retrieve the selected color scheme from cookies or use 'default' if not found
    selected_scheme = sanitize_input(request.cookies.get('color_scheme', 'default'))

    # Get the color scheme based on the selected option
    color_scheme = get_color_scheme(selected_scheme)
    return render_template('create-account.html', page='create account', color_scheme=color_scheme)


@app.route('/handle-registration', methods=['POST'])
def handle_registration():
    if request.method == 'POST':
        data = request.get_json()  # Parse JSON data from the request
        sanitized_data = {}

        for key, value in data.items():
            sanitized_data[key] = sanitize_input(value)

        input_username = sanitized_data.get('username')
        password = sanitize_input(sanitized_data.get('password'))
        firstName = sanitized_data.get('firstName')

        # Normalize the input username
        normalized_input_username = normalize(input_username)
        print(firstName)
        if not normalized_input_username or not password:
            flash('Username and password are required', 'error')
            print("Missing Information")
            return redirect(url_for('create_account'))

        # Check if the normalized input username already exists in the database
        existing_user = User.query.filter_by(username=normalized_input_username).first()
        print(normalized_input_username)

        if existing_user:
            flash('Username already exists', 'error')
            print("Existing User")
            abort(409, description='Username already exists')
        else:
            user = User(username=normalized_input_username, password=password, firstName=firstName)
            db.session.add(user)
            db.session.commit()
            print("Account Created Successfully")

            session['user_id'] = user.id
            flash('Account created successfully', 'success')
            return redirect(url_for('set_appearance'))

    return render_template('set-appearance.html')


@app.route('/set-appearance')
def set_appearance():
    # Retrieve the selected color scheme from cookies or use 'default' if not found
    selected_scheme = sanitize_input(request.cookies.get('color_scheme', 'default'))

    # Get the color scheme based on the selected option
    color_scheme = get_color_scheme(selected_scheme)
    return render_template('set-appearance.html', page='set appearance', color_scheme=color_scheme)


@app.route('/welcome')
def welcome():
    # Retrieve the selected color scheme from cookies or use 'default' if not found
    selected_scheme = sanitize_input(request.cookies.get('color_scheme', 'default'))

    # Get the color scheme based on the selected option
    color_scheme = get_color_scheme(selected_scheme)
    return render_template('welcome.html', page='welcome', color_scheme=color_scheme)


@app.route('/users')
def users():
    users = User.query.all()
    return render_template('users.html', users=users)


# Add a new protected route to fetch the user's username
@app.route('/get-username', methods=['GET'])
def get_username():
    if 'user_id' in session:
        current_user_id = session['user_id']
        user = User.query.get(current_user_id)
        print("User Requested")
        if user:
            print("User Signed In")
            return jsonify({'username': user.username, 'firstName': user.firstName}), 200
        else:
            print("User Doesn't Exist")
            return jsonify({'message': 'User not found'}), 404
    else:
        # Handle the case where 'user_id' is not in session
        print("User Not Authenticated")
        return jsonify({'message': 'User not authenticated'}), 401  # Return HTTP 401 Unauthorized


@app.route('/logout', methods=['GET'])
def logout():
    # Check if the user is signed in
    if 'user_id' in session:
        # Clear the session to log the user out
        session.clear()
        return jsonify({'message': 'Logged out successfully'}), 200
    else:
        # User is not signed in
        return jsonify({'message': 'User is not signed in'}), 401


@app.route('/delete-account', methods=['POST'])
def delete_account():
    if 'user_id' in session:
        current_user_id = session['user_id']
        user = sanitize_input(User.query.get(current_user_id))

        if user:
            db.session.delete(user)
            db.session.commit()
            # Clear the session
            session.clear()
            return jsonify({'message': 'Your account has been deleted.'}), 200
        else:
            return jsonify({'message': 'User not found'}), 404
    else:
        return jsonify({'message': 'User not authenticated'}), 401


@app.route('/')
def index():
    # Retrieve the selected color scheme from cookies or use 'default' if not found
    selected_scheme = sanitize_input(request.cookies.get('color_scheme', 'default'))
    # Get the color scheme based on the selected option
    color_scheme = get_color_scheme(selected_scheme)
    lowered_secondary_color = hoverBackgroundColor(color_scheme['secondary_color'])
    return render_template('layout.html', page='layout', color_scheme=color_scheme,
                           lowered_secondary_color=lowered_secondary_color)


@app.route('/saved-recipes')
def saved_recipes():
    detailed_recipes = Recipe.query.all()
    # Retrieve the selected color scheme from cookies or use 'default' if not found
    selected_scheme = sanitize_input(request.cookies.get('color_scheme', 'default'))

    # Get the color scheme based on the selected option
    color_scheme = get_color_scheme(selected_scheme)
    # Filter out incomplete or invalid entries
    detailed_recipes_data = [
        {
            'name': recipe.name,
            'description': recipe.description if recipe.description else "",  # Handle NULL descriptions
            'ingredients': [ingredient.name for ingredient in recipe.ingredients],
            'portions': recipe.portions if recipe.portions else "",  # Handle NULL portions
            'instructions': recipe.instructions if recipe.instructions else "",  # Handle NULL instructions
            'glass': recipe.glass if recipe.glass else "",  # Handle NULL glass
        }
        for recipe in detailed_recipes
        if recipe.name is not None  # Filter out entries with NULL names
    ]

    return render_template('saved-recipes.html', detailed_recipes_data=detailed_recipes_data, page='saved-recipes',
                           color_scheme=color_scheme)


@app.route('/get-available-recipes')
def get_available_recipes():
    addable_recipes = Recipe.query.all()
    recipe_names = [recipe.name for recipe in addable_recipes]
    return jsonify({'addable_recipes': recipe_names})


@app.route('/get-available-liquors')
def get_available_liquors():
    available_liquors = get_liquor_list()
    return available_liquors


@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username'))
        normalUsername = normalize(username)
        user = User.query.filter_by(username=normalUsername).first()
        password = sanitize_input(request.form.get('password'))

        if user is not None:
            print("Account Exists")
            Hashed = user.password.encode()
            Input = password.encode()
            print(f"Hashed Code: {Hashed}")
            print(f"Input Code: {Input}")
            print(f"Username: {username} Password: {password}")
            if user and bcrypt.check_password_hash(user.password, password):
                print("SIGNED IN!!!")
                flash('Login successful!', 'success')
                session['user_id'] = user.id

                # Redirect to the settings page with signed_in set to True
                return redirect(url_for('settings'))
            else:
                print("ERROR")

    # Retrieve the selected color scheme from cookies or use 'default' if not found
    selected_scheme = sanitize_input(request.cookies.get('color_scheme', 'default'))

    # Get the color scheme based on the selected option
    color_scheme = get_color_scheme(selected_scheme)
    lowered_secondary_color = hoverBackgroundColor(color_scheme['secondary_color'])
    if 'user_id' in session:
        # User is signed in, retrieve user data as needed
        user_id = session['user_id']
        user = User.query.get(user_id)
        is_admin = is_user_admin(user.id)
        print(f"Is Admin: {is_admin}")
        # Pass user data to the template with signed_in set to True
        return render_template('settings.html', page='settings', color_scheme=color_scheme, signed_in=True, user=user,
                               is_admin=is_admin, lowered_secondary_color=lowered_secondary_color)

    # User is not signed in, pass signed_in as False
    return render_template('settings.html', page='settings', color_scheme=color_scheme, signed_in=False,
                           lowered_secondary_color=lowered_secondary_color)


# You can keep the '/settings' route for displaying the settings page
@app.route('/profile')
def profile():
    # You can have a separate route for the profile page
    if 'user_id' in session:
        user = sanitize_input(User.query.get(session['user_id']))
        return render_template('profile.html', user=user)
    else:
        return redirect(url_for('settings'))


@app.route('/mix')
def mix():
    current_recipes = Recipe.query.all()
    liquor_colors = LiquorType.query.all()
    # Retrieve the selected color scheme from cookies or use 'default' if not found
    selected_scheme = sanitize_input(request.cookies.get('color_scheme', 'default'))

    # Get the color scheme based on the selected option
    color_scheme = get_color_scheme(selected_scheme)

    dark = color_scheme['dark'] == 'true'

    return render_template('mix.html', dark=dark, current_recipes=current_recipes, liquor_type=liquor_colors,
                           page='mix', color_scheme=color_scheme)


@app.route('/set-color-scheme/<selected_scheme>')
def set_color_scheme(selected_scheme):
    # Set a cookie to store the selected color scheme
    response = make_response(redirect('/'))
    response.set_cookie('color_scheme', selected_scheme)
    return response


@app.route('/add-unlisted-recipe')
def add_unlisted_recipe():
    existing_recipes = []
    # Retrieve the selected color scheme from cookies or use 'default' if not found
    selected_scheme = sanitize_input(request.cookies.get('color_scheme', 'default'))

    # Get the color scheme based on the selected option
    color_scheme = get_color_scheme(selected_scheme)
    return render_template('add-unlisted-recipe.html', existing_recipes=existing_recipes, glass_options=glass_options,
                           page="add-unlisted-recipe", color_scheme=color_scheme)


@app.route('/submit-unlisted-recipe', methods=['POST'])
def submit_unlisted_recipe():
    # Retrieve the selected color scheme from cookies or use 'default' if not found
    selected_scheme = sanitize_input(request.cookies.get('color_scheme', 'default'))

    # Get the color scheme based on the selected option
    color_scheme = get_color_scheme(selected_scheme)
    try:
        # Print the incoming form data for debugging
        print("Incoming Form Data:")
        for key, value in request.form.items():
            print(f"{key}: {value}")

        recipe_name = sanitize_input(request.form['recipe-name'])
        recipe_description = sanitize_input(request.form['recipe-description'])
        recipe_portions = sanitize_input(request.form['recipe-portions'])
        recipe_instructions = sanitize_input(request.form['recipe-instructions'])
        recipe_glass = sanitize_input(request.form['recipe-glass'])

        # Assuming that 'recipe-ingredients' is a string containing ingredients separated by newlines
        recipe_ingredients_json = request.form['ingredient-list']
        recipe_ingredients = json.loads(recipe_ingredients_json)
        recipe_ingredients = [ingredient.strip().capitalize() for ingredient in recipe_ingredients]

        # Get the ingredient types from the client-side
        ingredient_types_json = sanitize_input(request.form['ingredient-types'])
        ingredient_types = json.loads(ingredient_types_json)

        ingredient_categories_json = sanitize_input(request.form['ingredient-categories'])
        ingredient_categories = json.loads(ingredient_categories_json)

        # Initialize a list to store selected ingredient types for 'liquor' category
        selected_liquor_types = []

        existing_recipe = Recipe.query.filter_by(name=recipe_name).first()

        if existing_recipe:
            return render_template('add-unlisted-recipe.html', existing_recipe_name=existing_recipe.name,
                                   item_already_exists=True, color_scheme=color_scheme)

        # Check if the recipe is already in available_recipes
        if any(recipe_data['name'] == recipe_name for recipe_data in available_recipes):
            custom = False  # Not a custom recipe if it's in available_recipes
        else:
            custom = True  # Custom recipe if not found in available_recipes

        for category, types in zip(ingredient_categories, ingredient_types):
            print("Looking at a Type")
            print(types)
            if category == 'liquor':
                print("Added to array")
                selected_liquor_types.append(types)  # Append the entire 'types' string as one item
                print(selected_liquor_types)

        # Ensure that selected liquor types are unique and sorted
        selected_liquor_types = sorted(set(selected_liquor_types))
        print(selected_liquor_types)
        # Join the selected liquor types by ', ' to create a string
        selected_liquor_types_str = ', '.join(selected_liquor_types)

        new_recipe = Recipe(
            name=recipe_name,
            description=recipe_description,
            portions=recipe_portions,
            instructions=recipe_instructions,
            glass=recipe_glass,
            custom=custom,
            ingredient_types=selected_liquor_types_str  # Store ingredient types in the new column
        )

        for ingredient_name, ingredient_type, ingredient_category in zip(recipe_ingredients, ingredient_types,
                                                                         ingredient_categories):
            ingredient = Ingredient(name=ingredient_name)
            ingredient.type = ingredient_type
            ingredient.category = ingredient_category
            new_recipe.ingredients.append(ingredient)

        # Add the new recipe to the database
        db.session.add(new_recipe)
        db.session.commit()

        return jsonify({'success': True})  # Adjust this response as needed

    except Exception as e:
        # Print any exception that occurs during processing for debugging
        print(f"Error: {str(e)}")
        return jsonify({'error': str(e)}), 500  # Return an error response with the error message


@app.route('/ingredients')
def ingredients():
    current_liquors = Liquor.query.all()
    current_mixers = Mixer.query.all()
    current_garnishes = Garnish.query.all()
    # Retrieve the selected color scheme from cookies or use 'default' if not found
    selected_scheme = sanitize_input(request.cookies.get('color_scheme', 'default'))

    # Get the color scheme based on the selected option
    color_scheme = get_color_scheme(selected_scheme)
    return render_template('ingredients.html', current_liquors=current_liquors, current_mixers=current_mixers,
                           current_garnishes=current_garnishes,
                           page='ingredients', color_scheme=color_scheme)


@app.route('/select-item', methods=['POST'])
def select_item():
    item_id = request.form['item_id']
    if item_id not in selected_items:
        selected_items.append(item_id)
    else:
        selected_items.remove(item_id)
    return jsonify({'selected_items': selected_items})


@app.route('/delete-selected', methods=['POST'])
def delete_selected():
    item_id = request.json['item_id']
    item_type = request.json['item_type']

    # Assuming you have an ID-based logic to delete items from the database
    if item_type == 'liquor':
        item = db.session.get(Liquor, item_id)  # Get the Liquor object
        if item:
            item_text = item.name  # Assuming the name attribute contains the text content
        else:
            return jsonify({'error': 'Item not found'})
    elif item_type == 'mixer':
        item = db.session.get(Mixer, item_id)  # Get the Mixer object
        if item:
            item_text = item.name  # Assuming the name attribute contains the text content
        else:
            return jsonify({'error': 'Item not found'})
    elif item_type == 'garnish':
        item = db.session.get(Garnish, item_id)  # Get the Garnish object
        if item:
            item_text = item.name  # Assuming the name attribute contains the text content
        else:
            return jsonify({'error': 'Item not found'})
    else:
        return jsonify({'error': 'Invalid item type'})

    sanitized_item = sanitize_input(item_text)  # Pass the text content to sanitize_input

    if sanitized_item:
        db.session.delete(item)
        db.session.commit()

    return jsonify({'deleted_item': item_id})


@app.route('/add-liquor')
def add_liquor():
    available_liquors = get_liquor_list()
    # Retrieve the selected color scheme from cookies or use 'default' if not found
    selected_scheme = sanitize_input(request.cookies.get('color_scheme', 'default'))

    # Get the color scheme based on the selected option
    color_scheme = get_color_scheme(selected_scheme)
    return render_template('add-liquor.html', color_scheme=color_scheme, available_liquors=available_liquors)


@app.route('/add_product', methods=['POST'])
def add_product():
    data = request.get_json()
    barcode = data.get('barcode')

    # Make a request to the UPCITEMDB API to get product details
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'Accept-Encoding': 'gzip, deflate'
    }

    payload = {
        'upc': barcode
    }

    response = requests.post(UPCITEMDB_API_URL, headers=headers, json=payload)

    if response.status_code == 200:
        product_details = response.json()
        product_list.append(product_details)
        return jsonify(message='Product added successfully'), 201
    else:
        return jsonify(message='Product not found'), 404


@app.route('/get_products', methods=['GET'])
def get_products():
    return jsonify(products=product_list)


@app.route('/submit-liquor')
def submit_liquor():
    # Get query parameters
    liquor_name = request.args.get('name')
    liquor_type = request.args.get('type')
    abv = request.args.get('abv')

    # Check if any of the query parameters are None
    if liquor_name is None or liquor_type is None:
        print('Invalid input parameters: name={}, type={}, abv=None'.format(liquor_name, liquor_type))
        return jsonify({'added': False, 'message': 'Invalid input parameters'})

    # Sanitize input
    liquor_name = sanitize_input(liquor_name)
    liquor_type = sanitize_input(liquor_type)

    # Print the sanitized input for debugging
    print('Sanitized input: name={}, type={}, abv={}'.format(liquor_name, liquor_type, abv))

    # Check if the liquor already exists
    existing_liquor = Liquor.query.filter_by(name=liquor_name, type=liquor_type, abv=abv, custom=False).first()

    if existing_liquor:
        print('Found existing item: name={}, type={}, abv={}'.format(existing_liquor.name, existing_liquor.type,
                                                                     existing_liquor.abv))
        return jsonify({'added': False, 'message': 'This item is already in Our Bar'})

    # Create a new liquor record
    new_liquor = Liquor(name=liquor_name, type=liquor_type, abv=abv if abv is not None else None)
    db.session.add(new_liquor)
    db.session.commit()

    return jsonify({'added': True})


# Define the default liquor types
default_liquor_types = ['Beer', 'Brandy', 'Gin', 'Rum', 'Tequila', 'Vermouth', 'Vodka', 'Whiskey', 'Wine', 'Other']


@app.route('/add-unlisted-liquor')
def add_unlisted_liquor():
    global available_liquor_types
    existing_liquor = []  # Define an empty list for existing liquors

    csv_file_path = os.path.join(app.root_path, 'instance', 'default_liquor.csv')
    with open(csv_file_path, 'r', newline='') as csvfile:
        csv_reader = csv.DictReader(csvfile)
        for row in csv_reader:
            liquor_type = row['type']
            if liquor_type not in available_liquor_types:
                available_liquor_types.append(liquor_type)

    # Add default liquor types if they are not already in available_liquor_types
    for liquor_type in default_liquor_types:
        if liquor_type not in available_liquor_types:
            available_liquor_types.append(liquor_type)

    # Sort the list alphabetically
    available_liquor_types.sort()

    # Move "Other" to the end of the list if it exists
    if "Other" in available_liquor_types:
        available_liquor_types.remove("Other")
        available_liquor_types.append("Other")

    # Retrieve the selected color scheme from cookies or use 'default' if not found
    selected_scheme = sanitize_input(request.cookies.get('color_scheme', 'default'))
    print("Running")
    # Get the color scheme based on the selected option
    color_scheme = get_color_scheme(selected_scheme)
    return render_template('add-unlisted-liquor.html', color_scheme=color_scheme,
                           available_liquor_types=available_liquor_types,
                           existing_liquor=existing_liquor)


@app.route('/submit-unlisted-liquor', methods=['POST'])
def submit_unlisted_liquor():
    liquor_name = sanitize_input(request.form['liquor-name'])
    liquor_type = sanitize_input(request.form['liquor-type'])
    abv = sanitize_input(request.form['abv'] + '%')

    existing_liquor = Liquor.query.filter_by(name=liquor_name, type=liquor_type, abv=abv).first()

    if existing_liquor:
        return render_template('add-unlisted-liquor.html', existing_liquor_name=existing_liquor.name,
                               existing_liquor_type=existing_liquor.type, available_liquor_types=available_liquor_types,
                               item_already_exists=True)

    new_liquor = Liquor(name=liquor_name, abv=abv, type=liquor_type, custom=True)

    # Add the new liquor to the database
    db.session.add(new_liquor)
    db.session.commit()
    return redirect('ingredients')  # Redirect to the 'ingredients' route


@app.route('/add-mixer')
def add_mixer():
    available_mixers = []
    # Retrieve the selected color scheme from cookies or use 'default' if not found
    selected_scheme = sanitize_input(request.cookies.get('color_scheme', 'default'))

    # Get the color scheme based on the selected option
    color_scheme = get_color_scheme(selected_scheme)
    # Construct the path to the default_mixers.csv file in the instance folder
    csv_file_path = os.path.join(app.root_path, 'instance', 'default_mixers.csv')

    with open(csv_file_path, 'r', newline='') as csvfile:
        mixer_reader = csv.DictReader(csvfile)
        for row in mixer_reader:
            # print(row)  # Add this line to print each row
            mixer_name = row['name']
            mixer_type = row['type']
            mixer_custom = row['custom']

            existing_mixer = Mixer.query.filter_by(name=mixer_name, type=mixer_type).first()
            if not existing_mixer:
                available_mixers.append(row)

    return render_template('add-mixer.html', color_scheme=color_scheme, available_mixers=available_mixers)


@app.route('/submit-mixer')
def submit_mixer():
    mixer_name = sanitize_input(request.args.get('name'))
    mixer_type = sanitize_input(request.args.get('type'))

    existing_mixer = Mixer.query.filter_by(name=mixer_name, type=mixer_type).first()

    if existing_mixer:
        return jsonify({'added': False, 'message': 'This item is already in Our Bar'})

    new_mixer = Mixer(name=mixer_name, type=mixer_type, custom=False)
    db.session.add(new_mixer)
    db.session.commit()

    return jsonify({'added': True})


@app.route('/add-unlisted-mixer')
def add_unlisted_mixer():
    global available_mixer_types
    available_mixer_types = ['Bitters', 'Fruit Juice', 'Garnish', 'Liqueurs', 'Soda', 'Other']
    existing_mixer = []  # Define an empty list for existing mixers
    # Retrieve the selected color scheme from cookies or use 'default' if not found
    selected_scheme = sanitize_input(request.cookies.get('color_scheme', 'default'))

    # Get the color scheme based on the selected option
    color_scheme = get_color_scheme(selected_scheme)
    return render_template('add-unlisted-mixer.html', color_scheme=color_scheme,
                           available_mixer_types=available_mixer_types,
                           existing_mixer=existing_mixer)


@app.route('/submit-unlisted-mixer', methods=['POST'])
def submit_unlisted_mixer():
    mixer_name = sanitize_input(request.form['mixer-name'])
    mixer_type = sanitize_input(request.form['mixer-type'])

    existing_mixer = Mixer.query.filter_by(name=mixer_name, type=mixer_type).first()

    if existing_mixer:
        return render_template('add-unlisted-mixer.html', existing_mixer_name=existing_mixer.name,
                               existing_mixer_type=existing_mixer.type, available_mixer_types=available_mixer_types,
                               item_already_exists=True)

    new_mixer = Mixer(name=mixer_name, type=mixer_type, custom=True)

    # Add the new mixer to the database
    db.session.add(new_mixer)
    db.session.commit()
    return redirect('ingredients')  # Redirect to the 'ingredients' route


@app.route('/add-garnish')
def add_garnish():
    available_garnishes = []

    # Construct the path to the default_garnishes.csv file in the instance folder
    csv_file_path = os.path.join(app.root_path, 'instance', 'default_garnishes.csv')
    # Retrieve the selected color scheme from cookies or use 'default' if not found
    selected_scheme = sanitize_input(request.cookies.get('color_scheme', 'default'))

    # Get the color scheme based on the selected option
    color_scheme = get_color_scheme(selected_scheme)
    with open(csv_file_path, 'r', newline='') as csvfile:
        garnish_reader = csv.DictReader(csvfile)
        for row in garnish_reader:
            # (row)  # Add this line to print each row
            garnish_name = row['name']
            garnish_type = row['type']
            garnish_custom = row['custom']

            existing_garnish = Garnish.query.filter_by(name=garnish_name, type=garnish_type).first()
            if not existing_garnish:
                available_garnishes.append(row)

    return render_template('add-garnish.html', color_scheme=color_scheme, available_garnishes=available_garnishes)


@app.route('/submit-garnish')
def submit_garnish():
    garnish_name = sanitize_input(request.args.get('name'))
    garnish_type = sanitize_input(request.args.get('type'))

    existing_garnish = Garnish.query.filter_by(name=garnish_name, type=garnish_type).first()

    if existing_garnish:
        return jsonify({'added': False, 'message': 'This item is already in Our Bar'})

    new_garnish = Garnish(name=garnish_name, type=garnish_type, custom=False)
    db.session.add(new_garnish)
    db.session.commit()

    return jsonify({'added': True})


@app.route('/add-unlisted-garnish')
def add_unlisted_garnish():
    global available_garnish_types
    available_garnish_types = ['Bitters', 'Fruit Juice', 'Liqueurs', 'Soda', 'Other']
    existing_garnish = []  # Define an empty list for existing garnishes
    # Retrieve the selected color scheme from cookies or use 'default' if not found
    selected_scheme = sanitize_input(request.cookies.get('color_scheme', 'default'))

    # Get the color scheme based on the selected option
    color_scheme = get_color_scheme(selected_scheme)
    return render_template('add-unlisted-garnish.html', color_scheme=color_scheme,
                           available_garnish_types=available_garnish_types,
                           existing_garnish=existing_garnish)


@app.route('/submit-unlisted-garnish', methods=['POST'])
def submit_unlisted_garnish():
    garnish_name = sanitize_input(request.form['garnish-name'])
    garnish_type = sanitize_input(request.form['garnish-type'])

    existing_garnish = Garnish.query.filter_by(name=garnish_name, type=garnish_type).first()

    if existing_garnish:
        return render_template('add-unlisted-garnish.html', existing_garnish_name=existing_garnish.name,
                               existing_garnish_type=existing_garnish.type,
                               available_garnish_types=available_garnish_types,
                               item_already_exists=True)

    new_garnish = Garnish(name=garnish_name, type=garnish_type, custom=True)

    # Add the new garnish to the database
    db.session.add(new_garnish)
    db.session.commit()
    return redirect('ingredients')  # Redirect to the 'ingredients' route


@app.errorhandler(404)
def page_not_found(e):
    # Retrieve the selected color scheme from cookies or use 'default' if not found
    selected_scheme = sanitize_input(request.cookies.get('color_scheme', 'default'))

    # Get the color scheme based on the selected option
    color_scheme = get_color_scheme(selected_scheme)
    return render_template('404.html', color_scheme=color_scheme), 404


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
