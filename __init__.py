#!/usr/bin/env python
#-*- coding:utf8 -*-

from flask import Flask
from flask.ext.bootstrap import Bootstrap
from flask.ext.mail import Mail
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.script import Manager, Shell
from flask.ext.login import LoginManager

bootstrap = Bootstrap()
mail = Mail()
db = SQLAlchemy()
login_manager = LoginManager()
login_manager.session_protection = 'strong'
login_manager.login_view = 'auth.login'

class appFactory(object):
	'''
	Factory模式，学习设计模式中...
	'''
	def __init__(self):
		pass

	@staticmethod
	def create_app():

		global db, bootstrap, mail, login_manager
		app = Flask(__name__)

		from main import main as main_blueprint
		from auth import auth as auth_blueprint

		app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://flask:gf37888676@172.17.0.25/flask'
		app.config['SQLAlCHEMY_COMMIT_ON_TEARDOWN'] = True
		app.config['FLASK_MAIL_SUBJECT_PREFIX'] = '[Flasky]'
		app.config['FLASK_MAIL_SENDER'] = 'Flasky Admin <iamawar3player@163.com>'
		app.config['MAIL_SERVER'] = 'smtp.163.com'
		app.config['MAIL_PORT'] = 25
		app.config['MAIL_USE_TLS'] = False
		app.config['MAIL_USERNAME'] = 'iamawar3player@163.com'
		app.config['MAIL_PASSWORD'] = 'fan86797121'
		app.config['DEBUG'] = True
		app.config['SECRET_KEY'] = 'gf37888676'
		app.register_blueprint(main_blueprint)
		app.register_blueprint(auth_blueprint, url_prefix='/auth')

		db = db.init_app(app)
		mail = mail.init_app(app)
		bootstrap = bootstrap.init_app(app)
		login_manager = login_manager.init_app(app)

		return app
