from flask import Flask, render_template, request, redirect, session, flash
from mysqlconnection import connectToMySQL
from flask_bcrypt import Bcrypt
import re 
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

app = Flask(__name__)
app.secret_key = "Secret"
bcrypt = Bcrypt(app)

USER_KEY = "user_id"

@app.route('/')
def login_register():
    mysql = connectToMySQL('login_registration')
    users = mysql.query_db('SELECT * FROM users;')
    print(users)
    return render_template('login_register_page.html')

@app.route('/register', methods =['POST'])
def register():
    is_valid = True
    if len(request.form['fname']) < 2:
        is_valid = False
        flash('Please enter a first name')

    if len(request.form['lname']) < 2:
        is_valid = False
        flash('Please enter a last name')   

    if not EMAIL_REGEX.match(request.form['email']):
        flash ("Invalid email address!")
        return redirect('/') 
    
    if not is_valid:   
        return redirect('/') 
    else:
        hashed_password = bcrypt.generate_password_hash(request.form['password'])
        password_string = request.form['confirm_password']
        is_match = bcrypt.check_password_hash(hashed_password, password_string)
        
        if is_match:
            mysql = connectToMySQL('login_registration')
            query = "INSERT INTO users (first_name, last_name, email, password) VALUES (%(fn)s, %(ln)s, %(em)s, %(hp)s);"
            data = {
                'fn' : request.form['fname'],
                'ln' : request.form['lname'],
                'em' : request.form['email'],
                'pw' : request.form['password'],
                'hp' : hashed_password 
            }
            user_id = mysql.query_db(query, data)
            session[USER_KEY] = user_id
            return redirect('/main_page')

@app.route('/main_page')
def main_page():
    mysql = connectToMySQL('login_registration')
    query = "SELECT * FROM users WHERE id = %(id)s"
    data = {'id': session[USER_KEY]}
    user_id = mysql.query_db(query, data)
    return render_template('main_page.html', users = user_id)

@app.route('/login', methods=['POST'])
def login():
    mysql = connectToMySQL('login_registration')
    query = 'SELECT id, password FROM users WHERE email = %(em)s'
    data = { 'em' : request.form['email']}
    user_id= mysql.query_db(query, data)
    
    if bcrypt.check_password_hash(user_id[0]['password'], request.form['password']):
        session[USER_KEY] = user_id[0]['id']
        return redirect('/main_page')


if __name__ == "__main__":
    app.run(debug=True)

