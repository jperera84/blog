""" Comment Handler """
import time
import webapp2
import jinja2
from handlers.handler import Handler
from models.entry import Entry
from models.user import User
from models.entryuserlikes import EntryUserLikes
from google.appengine.ext import ndb

class EntryLike(Handler):
    """ EntryLike Handler """
    def post(self):
        """ Default post method"""
        user_url = self.request.cookies.get('user_key', None)
        if user_url:
            user = ndb.Key(urlsafe=user_url).get()
            key_url = self.request.get("entry_key")
            if key_url:
                post = ndb.Key(urlsafe=key_url).get()
                if post and user:
                    if post.user_id != user.key.id():
                        like = EntryUserLikes(entry_id=post.key.id(), user_id=user.key.id())
                        like.put()
                        time.sleep(0.1)
                        self.redirect("/blog")
                    else:
                        self.redirect("/blog")
        else:
            self.redirect("/blog/login")
