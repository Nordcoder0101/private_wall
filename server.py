from flask import Flask, render_template, request, redirect, flash, session
from mysqlconnection import connectToMySQL
from flask_bcrypt import Bcrypt
import re


app = Flask(__name__)
app.secret_key = 'lololol'
bcrypt = Bcrypt(app)

def find_number_of_messages_for_logged_in_user(list):
  length_of_message = 0
  for message in list:
      if message['sent_to_id'] == session['logged_in_user']:
        length_of_message += 1
  return length_of_message      


EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')


@app.route("/")
def index():

    return render_template('index.html')


@app.route("/register_account", methods=["POST"])
def validate_and_create_email():
    mysql = connectToMySQL('the_wall')
    emails = mysql.query_db('SELECT email FROM user')
    isValid = True
    first_name = request.form['first_name']
    last_name = request.form['last_name']
    email = request.form['email']
    print(request.form['password'])
    print(request.form['vpassword'])

    if len(request.form['password']) > 0 and request.form['password'] == request.form['vpassword']:
        pw_hash = bcrypt.generate_password_hash(request.form['password'])

    else:
        isValid == False
        flash("Please provide a password", 'fail')

    if len(first_name) < 2:
      isValid = False
      flash(u"Please enter a valid First Name", "fail")

    if len(last_name) < 2:
      isValid = False
      flash(u"Please enter a valid Last Name", "fail")

    if not EMAIL_REGEX.match(email):
        isValid = False
        flash(u"Invalid Email Address", 'fail')

    for db_email in emails:
        print(db_email)
        if db_email['email'] == email:
            isValid = False
            flash('email already exists in database')

    if isValid == True:

        query = 'INSERT INTO user (first_name, last_name, email, password_hash) VALUES (%(fn)s, %(ln)s, %(e)s, %(ph)s)'
        data = {
            'fn': first_name,
            'ln': last_name,
            'e': email,
            'ph': pw_hash
        }
        mysql = connectToMySQL('the_wall')
        new_email_id = mysql.query_db(query, data)
        flash(u"User successfully created", 'success')

    return redirect('/')


@app.route('/login', methods=["POST"])
def check_credentials_and_log_in():

    login_email = request.form['email']
    login_password = request.form['password']
    mysql = connectToMySQL('the_wall')
    users = mysql.query_db('SELECT id, email FROM user')

    for user in users:
        if user['email'] == login_email:
            print('matched **************')
            user_id = int(user['id'])

            mysql = connectToMySQL('the_wall')
            login_password_hash_and_email = mysql.query_db(
                f'select id, password_hash, email from user WHERE id = {user_id}')

            if bcrypt.check_password_hash(login_password_hash_and_email[0]['password_hash'], login_password):
                session['logged_in_user'] = login_password_hash_and_email[0]['id']

                flash(u'Login Successful', 'success')
                session.pop('_flashes', None)
                return redirect('/success')
        else:
          flash(u'Improper credentials', 'fail')

    return redirect('/')


@app.route("/success")
def show_success_page():
    
    mysql = connectToMySQL('the_wall')
    messages = mysql.query_db(
        'SELECT * FROM messages INNER JOIN user ON messages.created_by_id = user.id WHERE user.id = created_by_id')
    mysql = connectToMySQL('the_wall')
    users = mysql.query_db('SELECT * FROM user')
    
    for user in users:
        if user['id'] == session['logged_in_user']:
          current_user_name = user['first_name']

    length_of_message = find_number_of_messages_for_logged_in_user(messages)
    
    return render_template('wall.html', messages=messages, users=users, message_length=length_of_message, current_user_name=current_user_name)


@app.route('/post_message', methods=["POST"])
def post_new_message():
    if len(request.form['content']) < 5:
      flash('Your message needs to be at least 5 characters long', 'fail')
      return redirect('/success') 

    mysql = connectToMySQL('the_wall')
    query = 'INSERT INTO messages (content, created_by_id, sent_to_id, created_at) VALUES (%(comment)s, %(createdby)s, %(sentto)s, NOW())'
    data = {
      'comment': request.form['content'],
      'createdby': session['logged_in_user'],
      'sentto': request.form['recipiant']
    }
    new_message_id = mysql.query_db(query, data)
    return redirect('/success')

@app.route('/messages/<id>/delete')
def delete_message(id):
    mysql = connectToMySQL('the_wall')
    query = 'DELETE FROM messages WHERE id = %(id)s'
    data = {'id': id}
    mysql.query_db(query, data)
    flash('Message successfully deleted', 'success')
    return redirect('/success')

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == '__main__':
    app.run(debug=True)
