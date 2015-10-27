#!/usr/bin/env python
#-*- coding:utf8 -*-

from flask import SQLAlchemy

class User(db.model):
	__tablename__ = "users"
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(64), unique=True, index=True)
	password_hash = db.Column()
	email = db.Column(db.String(64), unique=True, index=True)
	confirmed = db.Column(db.Boolean)

	def __repr__(self):
		return '<User %r>' % self.username

class Role(db.model):
	__tablename__ = 'roles'
	id = db.Column(db.Integer, primary_key=True)
	name = db.Column(db.String(64), unique=True)

	def __repr__(self):
		return '<Role %r>' % self.name