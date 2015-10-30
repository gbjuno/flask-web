#!/usr/bin/env python
#-*- coding:utf8 -*-

from . import main
from .. import db, moment
from ..decorators import admin_required
from ..models import User, Role, Post
from flask import render_template,abort,redirect,url_for, flash, request, current_app
from flask.ext.login import current_user
from flask.ext.login import login_user, login_required, logout_user, current_user
from flask.ext.wtf import Form
from wtforms import TextAreaField, StringField, SelectField, PasswordField, SubmitField, RadioField, BooleanField, ValidationError, DateTimeField, IntegerField
from wtforms.validators import Required, Regexp, EqualTo, Email, Length
from flask.ext.pagedown.fields import PageDownField


class EditPostForm(Form):
	body = PageDownField("what's on your mind?", validators=[Required()])
	submit = SubmitField("post your mind")

class PostForm(Form):
	body = PageDownField("what's on your mind?", validators=[Required()])
	submit = SubmitField("post your mind")

class EditProfileForm(Form):
	age = IntegerField('age', validators=[Required()])
	about_me = TextAreaField('say something about you')
	submit = SubmitField()

class EditProfileAdminForm(Form):
	username = StringField('username', validators=[Required()])
	email = StringField('email', validators=[Required(), Email()])
	role = SelectField('role', coerce=int)
	age = IntegerField('age', validators=[Required()])
	about_me = TextAreaField('say something about you')
	submit = SubmitField()

	def __init__(self, user, *args, **kwargs):
		super(EditProfileAdminForm, self).__init__(*args, **kwargs)
		self.user = user
		self.role.choices = [(role.id, role.name) for role in Role.query.order_by(Role.name).all()]

	def validate_username(self, field):
		if field.data != self.user.username and  User.query.filter_by(username=field.data).first():
			raise ValidationError('Username already in use')

	def validate_email(self, field):
		if field.data != self.user.email and User.query.filter_by(email=field.data).first():
			raise ValidationError('Email already in use')

@main.route('/post/<int:id>')
def post(id):
	post = Post.query.get_or_404(id)
	if post is not None:
		return render_template('main/post.html', post=post)

@main.route('/editpost/<int:id>', methods=['GET','POST'])
@login_required
def editpost(id):
	post = Post.query.get_or_404(id)
	form = EditPostForm()
	if post is not None:
		if not current_user.is_administrator() and post.author != current_user._get_current_object():
			flash('you do not have permission to edit this article')
			return redirect(url_for('main.index'))
		if form.validate_on_submit():
			post.body = form.body.data
			db.session.add(post)
			db.session.commit()
			return redirect(url_for('main.post',id=id))
		form.body.data = post.body
		return render_template('main/editpost.html', post=post, form=form)

@main.route('/mypost', methods=['GET','POST'])
@login_required
def mypost():
	form = PostForm()
	if form.validate_on_submit():
		post = Post(body = form.body.data, author=current_user._get_current_object())
		db.session.add(post)
		db.session.commit()
		return redirect(url_for('main.index'))
	return render_template('main/editmypost.html', form=form)

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
	user = User.query.filter_by(username=username).first()
	form = EditProfileAdminForm(user=user)
	if user is not None:
		if form.validate_on_submit():
			user.username = form.username.data
			user.email = form.email.data
			user.age = form.age.data
			user.about_me = form.about_me.data
			db.session.add(user)
			db.session.commit()
			flash('edit user %s complete' % user.username)
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
	page = request.args.get('page', 1 ,type=int)
	pagination = Post.query.order_by(Post.timestamp.desc()).paginate(page, per_page = current_app.config['FLASKY_POSTS_PER_PAGE'], error_out=False)
	posts = pagination.items
	return render_template('main/index.html', user=user, posts=posts, pagination=pagination)

@main.app_errorhandler(404)
def page_not_found(e):
	return render_template('main/404.html'), 404

@main.app_errorhandler(500)
def internal_server_error(e):
	return render_template('main/500.html'), 500