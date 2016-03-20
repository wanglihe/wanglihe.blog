#!/usr/bin/env python
# -*- coding: utf-8 -*- #
from __future__ import unicode_literals

AUTHOR = u'王礼鹤'
SITENAME = u'王礼鹤的博客'
SITEURL = ''

PATH = 'content'

TIMEZONE = 'Asia/Shanghai'

DEFAULT_LANG = u'zh'
THEME = 'theme/voidy-bootstrap'

#vars for voidy-bootstrap
SKIP_DEFAULT_JS = True
JAVASCRIPT_FILES = (('bootstrap.min.js'),)
SKIP_DEFAULT_CSS = True
STYLESHEET_FILES = (('bootstrap.min.css'), ('font-awesome.min.css'),
                    ('pygment.css'), ('voidybootstrap.css'))
SIDEBAR = "sidebar.html"

# Feed generation is usually not desired when developing
FEED_ALL_ATOM = None
CATEGORY_FEED_ATOM = None
TRANSLATION_FEED_ATOM = None
AUTHOR_FEED_ATOM = None
AUTHOR_FEED_RSS = None

# Blogroll
#LINKS = (('Pelican', 'http://getpelican.com/'),
#         ('Python.org', 'http://python.org/'),
#         ('Jinja2', 'http://jinja.pocoo.org/'),
#         ('You can modify those links in your config file', '#'),)

# Social widget
#SOCIAL = (('You can add links in your config file', '#'),
#          ('Another social link', '#'),)

DEFAULT_PAGINATION = 20

PLUGIN_PATHS = ["plugins", "pelican-plugins"] #pelican-plugins为插件总目录
PLUGINS = ['tag_cloud', 'related_posts'] #插件总目录里的插件(文件夹)名

DISPLAY_TAGS_ON_SIDEBAR = True
TAG_CLOUD_MAX_ITEMS = 10000


# Uncomment following line if you want document-relative URLs when developing
#RELATIVE_URLS = True
