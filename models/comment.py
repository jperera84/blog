""" Entity Model Class Comment """

from google.appengine.ext import ndb

class Comment(ndb.Model):
    """ Comment class """
    content = ndb.TextProperty(required=True)
    created = ndb.DateTimeProperty(auto_now_add=True)
    entry_id = ndb.IntegerProperty(required=True)
    user_id = ndb.IntegerProperty(required=True)
    last_modified = ndb.DateTimeProperty(auto_now=True)
