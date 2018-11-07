from flask import Flask, render_template, request, redirect, flash, session
from mysqlconnection import connectToMySQL
from flask_bcrypt import Bcrypt
import re


app = Flask(__name__)
app.secret_key = 'lololol'
bcrypt = Bcrypt(app)

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')


@app.route("/")
def index():
  
    
    return render_template('index.html')


if __name__ =='__main__':
    app.run(debug=True)
