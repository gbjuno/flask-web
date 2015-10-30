#!/usr/bin/env python
#-*- coding:utf8 -*-

from . import admin
from .. import db
from ..utils import send_mail
from ..models import User, Role, Permission
from ..decorators import permission_required, admin_required
from flask import render_template, redirect, request, url_for, flash, current_app
from flask.ext.wtf import Form
from flask.ext.login import login_user, login_required, logout_user, current_user
from wtforms import StringField, PasswordField, SubmitField, RadioField, BooleanField, ValidationError
from wtforms.validators import Required, Regexp, EqualTo, Email, Length
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask import current_app

@admin.app_context_processor
def inject_permissions():
	return dict(Permission=Permission)

@admin.route('/')
@login_required
@admin_required
def index():
	return render_template('admin/index.html')

@admin.route('/moderator')
@login_required
@permission_required(Permission.MODERATE_COMMENTS)
def moderator():
	return render_template('admin/index.html')