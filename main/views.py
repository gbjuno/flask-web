#!/usr/bin/env python
#-*- coding:utf8 -*-

from . import main
from .. import db
from ..decorators import admin_required
from ..models import User
from flask import render_template,abort,redirect,url_for
from flask.ext.login import current_user
from flask.ext.login import login_user, login_required, logout_user, current_user
from flask.ext.wtf import Form
from wtforms import TextAreaField, StringField, PasswordField, SubmitField, RadioField, BooleanField, ValidationError, DateTimeField, IntegerField
from wtforms.validators import Required, Regexp, EqualTo, Email, Length

class EditProfileForm(Form):
	age = IntegerField('age', validators=[Required()])
	about_me = TextAreaField('say something about you')
	submit = SubmitField()


class EditProfileAdminForm(Form):
	username = StringField('username', validators=[Required()])
	email = StringField('email', validators=[Required(), Email()])
	age = IntegerField('age', validators=[Required()])
	about_me = TextAreaField('say something about you')
	submit = SubmitField()

	def validate_username(self, field):
		if User.query.filter_by(username=field.data).first():
			raise ValidationError('Username already in use')

	def validate_email(self, field):
		if User.query.filter_by(email=field.data).first():
			raise ValidationError('Email already in use')

@main.route('/user/<username>')
def user(username):
	user = User.query.filter_by(username=username).first()
	if user is None:
		abort(404)
	return render_template('main/myprofile.html', user=user)


@main.route('/user/edit/<username>', methods=['GET','POST'])
@login_required
def useredit(username):
	form = EditProfileForm()
	user = User.query.filter_by(username=username).first()
	if current_user != user:
		return redirect(url_for('main.useredit', username=current_user.username))
	if form.validate_on_submit():
		current_user.age = form.age.data
		current_user.about_me = form.about_me.data
		db.session.add(current_user)
		db.session.commit()
		return redirect(url_for('main.user',username=current_user.username))
	return render_template('main/editmyprofile.html', form=form, user=current_user)

@main.route('/user/adminedit/<username>', methods=['GET','POST'])
@login_required
@admin_required
def adminedit(username):
	form = EditProfileAdminForm()
	user = User.query.filter_by(username=username).first()
	if user is not None:
		if form.validate_on_submit():
			user.username = form.username.data
			user.email = form.email.data
			user.age = form.age.data
			user.about_me = form.about_me.data
			db.session.add(user)
			db.session.commit()
			flash('edit user %r complete' % user.username)
			return redirect(url_for('main.index'))
		form.username.data = user.username
		form.email.data = user.email
		form.age.data = user.age
		form.about_me.data =user.about_me
	return render_template('main/editmyprofile.html', form=form, user=user)

@main.route('/')
def index():
	user = None
	if current_user.is_authenticated:
		user = current_user
	return render_template('main/index.html', user=user)

@main.app_errorhandler(404)
def page_not_found(e):
	return render_template('main/404.html'), 404

@main.app_errorhandler(500)
def internal_server_error(e):
	return render_template('main/500.html'), 500