import html
import sqlite3
import uuid
from flask import Flask, request, jsonify, url_for, render_template, make_response, redirect

try:
    from .models import init_dataset, Database
except (ImportError, SystemError):
    from models import init_dataset, Database


app = Flask(__name__)
# Disable Flask's default protection
# All major frameworks enforce CSRF-protection in forms by default, in all POST views.
app.config['WTF_CSRF_ENABLED'] = False

csrf_token = str(uuid.uuid4())


@app.route('/', methods=['GET'])
def main():
    return redirect(url_for('account'))


@app.route('/account', methods=['GET'])
def account():
    with Database() as db:
        db.execute("select amount from accounts where username = 'user1'")
        data = db.fetchone()
    resp = make_response(render_template('account.html', current_account=data[0], csrf_token=csrf_token))
    # secret_token = request.cookies.get('secret')
    # if secret_token is None:
    #     resp.set_cookie('secret', csrf_token)
    return resp


@app.route('/withdraw', methods=['POST'])
def withdraw():
    username = html.escape(request.form.get("username"))
    password = html.escape(request.form.get("password"))
    secret = request.form.get("secret")
    
    print(username, password, secret)
    
    if username != 'user1' or password != 'password' or not secret or secret != csrf_token:
        return redirect(url_for('account'))

    with Database() as db:
        db.execute("select amount from accounts where username = ?", (username, ))
        data = db.fetchone()
    
    if not data:
        return redirect(url_for('account'))
    
    if data[0] > 0:
        with Database() as db:
            db.execute("update accounts set amount = amount - 1 where username = ?", (username, ))

    return redirect(url_for('account'))


@app.route('/danger', methods=['GET'])
def danger():
    return render_template('danger.html')


if __name__ == '__main__':
    init_dataset()
    app.run(debug=True)
