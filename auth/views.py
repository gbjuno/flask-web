#!/usr/bin/env python
#-*- coding:utf8 -*-

from . import auth
from .. import db
from ..utils import send_mail
from ..models import User,Role
from flask import render_template, redirect, request, url_for, flash, current_app
from flask.ext.wtf import Form
from flask.ext.login import login_user, login_required, logout_user, current_user
from wtforms import StringField, PasswordField, SubmitField, RadioField, BooleanField, ValidationError
from wtforms.validators import Required, Regexp, EqualTo, Email, Length
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask import current_app

class LoginForm(Form):
	username = StringField('username', validators=[Required()])
	password = PasswordField('password', validators=[Required()])
	remeber_me = BooleanField('keep me logged in')
	submit = SubmitField('login')

class RegisterForm(Form):
	username = StringField('username', validators=[Required(), Length(1,64), Regexp('^[A-Za-z0-9_.]*$', 0, 'Username must have only letters, numbers, dots or underscore')])
	password = PasswordField('input password', validators=[Required(),EqualTo('password_sec', message='Password must match')])
	password_sec = PasswordField('comfirm password', validators=[Required()])
	email = StringField('email', validators=[Required(), Length(1,64), Email()])
	submit = SubmitField('Register')

	def validate_username(self, field):
		if User.query.filter_by(username=field.data).first():
			raise ValidationError('Username already in use')

	def validate_email(self, field):
		if User.query.filter_by(email=field.data).first():
			raise ValidationError('Email already in use')

class ChangePasswordForm(Form):
	oldpassword = PasswordField('old password', validators=[Required()])
	newpassword = PasswordField('new password', validators=[Required(), EqualTo('newpassword_sec', message='Password must match')])
	newpassword_sec = PasswordField('confirm new password', validators=[Required()])
	submit = SubmitField('confirm')

class ForgetPasswordForm(Form):
	email = StringField('input your email address', validators=[Required(), Email()])
	submit = SubmitField('send reset password email')

@auth.route('/login', methods=['GET', 'POST'])
def login():
	form = LoginForm()
	if form.validate_on_submit():
		user = User.query.filter_by(username=form.username.data).first()
		if user is not None and user.verify_password(password=form.password.data):
			login_user(user, form.remeber_me.data)
			return redirect(request.args.get('next') or url_for('main.index'))
		flash('Invalid username or password')
	return render_template('auth/login.html', form=form)

@auth.route('/logout')
@login_required
def logout():
	logout_user()
	flash('You have been logged out.')
	return redirect(url_for('main.index'))

@auth.route('/register', methods=['GET', 'POST'])
def register():
	form = RegisterForm()
	if form.validate_on_submit():
		user = User(username=form.username.data, email=form.email.data, password = form.password.data)
		db.session.add(user)
		db.session.commit()
		send_mail(app=current_app, to=form.email.data,subject='Please confirm your account',template='register', username=form.username.data,confirm_url='http://10.35.89.23/auth/confirm/' + user.generate_confirmation_token())
		flash('Register done. A confirmation email has been sent to your account. Please check your email.')
		return redirect(url_for('auth.login'))
	return render_template('auth/register.html', form=form)

@auth.route('/resendmail')
@login_required
def resend_confirmation():
	token = current_user.generate_confirmation_token()
	send_mail(app=current_app, to=current_user.email,subject='Please confirm your account',template='register', username=current_user.username,confirm_url='http://10.35.89.23/auth/confirm/' + current_user.generate_confirmation_token())
	flash('A new confirmation mail has been sent to your email box!')
	return redirect(url_for('main.index'))

@auth.route('/confirm/<token>')
@login_required
def confirm_mail(token):
	if current_user.confirmed:
		return redirect(url_for('main.index'))
	if current_user.confirm(token):
		flash('you have confirmed your account. Thanks!')
	else:
		flash('the confirmation link is invalid or has expired')
	return redirect(url_for('main.index'))

@auth.before_app_request
def before_request():
	if current_user.is_authenticated and not current_user.confirmed and request.endpoint[:5] != 'auth.':
		return redirect(url_for('auth.unconfirmed'))

@auth.route('/unconfirmed')
def unconfirmed():
	if current_user.is_anonymous or current_user.confirmed:
		return redirect('main.index')
	return render_template('auth/unconfirm.html', user=current_user)

@auth.route('/change_password', methods=['GET','POST'])
@login_required
def change_password():
	form =  ChangePasswordForm()
	if form.validate_on_submit():
		oldpassword = form.oldpassword.data
		if current_user.verify_password(oldpassword):
			current_user.password = form.newpassword.data
			db.session.add(current_user)
			db.session.commit()
			flash('Password change sucessful!')
			return redirect(url_for('main.index'))
		else:
			flash('Please input correct old password!')
	return render_template('auth/change_password.html', form=form)

@auth.route('/forget_password', methods=['GET', 'POST'])
def forget_password():
	form = ForgetPasswordForm()
	if form.validate_on_submit():
		email = User.query.filter_by(email=form.email.data).first()
		if email is not None:
			send_mail(app=current_app, to=current_user.email,subject='Please reset your password, template='reset password', \
				username=current_user.username, confirm_url=url_for('auth.confirm') + current_user.generate_confirmation_token())
		else:
			flash("invalid user email address.")
	return render_template('auth/forget_password.html', form=form)

@auth.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password():
	passs

