#!/usr/bin/env python
#-*- coding:utf8 -*-

from . import main
from flask import render_template
from flask.ext.login import current_user

@main.route('/')
def index():
	user = None
	if current_user.is_authenticated:
		user = current_user
	return render_template('main/index.html', user=user)