from flask import redirect, render_template, session, request, flash
from flask_app import app
from flask_app.models.user import User
from flask_bcrypt import Bcrypt
bcrypt = Bcrypt(app)

@app.route('/')
def index():
	return render_template('index.html')

@app.route('/register/user', methods=['POST'])
def register():
	if not User.validate(request.form):
		return redirect('/')
	data = {
		"first_name": request.form["first_name"],
		"last_name": request.form['last_name'],
		"email" : request.form['email'],
		"birthday": request.form['birthday'],
		"password": bcrypt.generate_password_hash(request.form['password'])
	}
	id = User.save(data)
	session['id'] = id
	return redirect('/success')


@app.route('/login', methods = ['POST'])
def success_login():
	user= User.get_by_email(request.form)
	if not user:
		flash('Invalid Email.',"login")
		return redirect('/')
	if not bcrypt.check_password_hash(user.password, request.form['password']):
		flash('Invalid password/Password',"login")
		return redirect('/')
	session['id'] = user.id
	return redirect('/success')

@app.route('/success')
def success():
	if 'id' not in session:
		return redirect('/logout')
	data = {
		"id": session['id']
	}
	return render_template('success.html', user= User.get_by_id(data))


@app.route('/logout')
def logout():
	session.clear()
	return redirect('/')