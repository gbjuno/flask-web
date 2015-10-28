#!/usr/bin/env python
#-*- coding:utf8 -*-

from . import mail
from flask import render_template
from flask.ext.mail import Message

def send_mail(app, to, subject, template, **kwargs):
	msg = Message(app.config['FLASK_MAIL_SUBJECT_PREFIX'] + subject, sender=app.config['FLASK_MAIL_SENDER'], recipients=[to])
	msg.body = render_template('mail/' + template +'.txt', **kwargs)
	msg.html = render_template('mail/' + template +'.html', **kwargs)
	mail.send(msg)
