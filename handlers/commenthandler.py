""" Comment Handler """
import time
import webapp2
import jinja2
from handlers.handler import Handler
from models.entry import Entry
from google.appengine.ext import ndb

class CommentHandler(Handler):
    """Comment Handler class"""
    def get(self):
        """ Default get method """
        user_url = self.request.cookies.get('user_key', None)
        login_text = "Log In"
        logout_text = None
        if user_url:
            user = ndb.Key(urlsafe=user_url).get()
            user_id = ndb.Key(urlsafe=user_url).id()
            login_text = "Welcome %s" % user.username
            logout_text = "Logout"
            comment_edit_key_url = self.request.get("comment")
            entry_key_url = self.request.get("entry")
            comment_key = ndb.Key(urlsafe=comment_edit_key_url)
            comment = comment_key.get()
            if comment.user_id == user_id:
                if comment:
                    self.render("comment.html", login=login_text,
                                logout=logout_text, entry_key=entry_key_url,
                                comment_key=comment_edit_key_url,
                                comment=comment.content)
                else:
                    self.redirect("/blog/entry?entry=%s" % entry_key_url)
            else:
                self.redirect("/blog/entry?entry=%s" % entry_key_url)
        else:
            self.render("comment.html", login=login_text,
                        logout=logout_text, error="You must be login First")
    def post(self):
        """ Post method to handle modify comments """
        user_url = self.request.cookies.get('user_key', None)
        if user_url:
            user_id = ndb.Key(urlsafe=user_url).id()
            comment_edit_key_url = self.request.get("comment_key")
            comment_key = ndb.Key(urlsafe=comment_edit_key_url)
            entry_key_url = self.request.get("entry_key")
            comment = comment_key.get()
            if comment:
                if comment.user_id == user_id:
                    content = self.request.get('content')
                    comment.content = content
                    comment.put()
                    time.sleep(0.1)
                    self.redirect("/blog/entry?entry=%s" % entry_key_url)
                else:
                    self.error(404)
                    return
            else:
                self.error(404)
                return
