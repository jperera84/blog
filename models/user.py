""" Entity Model Class User """
from google.appengine.ext import ndb

class User(ndb.Model):
    """ User class"""
    username = ndb.StringProperty(required=True)
    password = ndb.StringProperty(required=True)
    email = ndb.StringProperty()
    registered = ndb.DateTimeProperty(auto_now_add=True)
