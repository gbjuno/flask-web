#!/usr/bin/env python
#-*- coding:utf8 -*-

from flask import Flask
from flask.ext.bootstrap import Bootstrap
from flask.ext.script import Manager

app = Flask(__name__)
app.config['SECRET_KEY'] = 'gfzq'
bootstrap = Bootstrap(app)
manager = Manager(app)

@app.route('/')
def index():
	return "<h1>hello world!</h1>"

if __name__ == '__main__':
	manager.run()
