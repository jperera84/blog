""" Comment Handler """
import time
import webapp2
import jinja2
from handlers.handler import Handler
from models.entry import Entry
from models.comment import Comment
from google.appengine.ext import ndb

class EntryView(Handler):
    """ Main Program class"""
    def get(self):
        """ Default get method"""
        entry_key = self.request.get("entry")
        entry = ndb.Key(urlsafe=entry_key).get()
        user_url = self.request.cookies.get('user_key', None)
        login_text = "Log In"
        logout_text = None
        if user_url:
            user = ndb.Key(urlsafe=user_url).get()
            login_text = "Welcome %s" % user.username
            logout_text = "Logout"
        self.render("entry.html", entry=entry, login=login_text, logout=logout_text)
