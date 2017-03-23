""" Handler class """
import os
import webapp2
import jinja2
from google.appengine.ext import ndb
import settings

TEMPLATE_DIR = os.path.join(settings.PROJECT_ROOT, 'templates')
JINJA_ENV = jinja2.Environment(loader=jinja2.FileSystemLoader(TEMPLATE_DIR), autoescape=True)

class Handler(webapp2.RequestHandler):
    """ Main Handler class"""
    def write(self, *a, **kw):
        """ Method to response the html"""
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        """ Method to render the template"""
        temp = JINJA_ENV.get_template(template)
        return temp.render(params)

    def render(self, template, **kw):
        """ Method to render the template"""
        self.write(self.render_str(template, **kw))
