""" Entity Model Class User """
from google.appengine.ext import ndb

class EntryUserLikes(ndb.Model):
    """ EntryUserLikes class"""
    created = ndb.DateTimeProperty(auto_now_add=True)
    entry_id = ndb.IntegerProperty(required=True)
    user_id = ndb.IntegerProperty(required=True)
