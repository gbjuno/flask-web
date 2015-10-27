#!/usr/bin/env python
#-*- coding:utf8 -*-

from flask import Flask
from flask.ext.bootstrap import Bootstrap
from flask.ext.mail import Mail
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.moment import Moment
from flask.ext.script import Manager, Shell

bootstrap = Bootstrap()
mail = Mail()
moment = Moment()
db = SQLAlchemy()

class appFactory(object):
	'''
	Factory模式，学习设计模式中...
	'''
	def __init__(self):
		pass

	@staticmethod
	def create_app(name):

		app = Flask(name)

		from main import main as main_blueprint
		from auth import auth as auth_blueprint

		app.register_blueprint(main_blueprint)
		app.register_blueprint(auth_blueprint)

		db = db.init_app(app)
		mail = mail.init_app(app)
		bootstrap = bootstrap.init_app(app)

		return app

if __name__ == '__main__':
	app = appFactory.create_app('blog')
	manager.run()
