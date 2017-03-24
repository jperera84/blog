""" CommentAdd Model Class Entry """
import time
import webapp2
import jinja2
from models.comment import Comment
from models.entry import Entry
from models.user import User
from handlers.handler import Handler
from google.appengine.ext import ndb

class CommentAddHandler(Handler):
    """ Main Program class"""
    def post(self):
        """ Post method that handle add, delete comments """
        entry_key_url = self.request.get("entry_key")
        entry_key = ndb.Key(urlsafe=entry_key_url)
        entry = ndb.Key(urlsafe=entry_key_url).get()
        if entry:
            comment_edit_key_url = self.request.get("comment_edit_key")
            comment_del_key_url = self.request.get("comment_del_key")
            user_url = self.request.cookies.get('user_key', None)
            login_text = "Log In"
            logout_text = None
            if user_url:
                user_id = ndb.Key(urlsafe=user_url).id()
                user = ndb.Key(urlsafe=user_url).get()
                login_text = "Welcome %s" % user.username
                logout_text = "Logout"
                if comment_del_key_url or comment_edit_key_url:
                    if comment_del_key_url:
                        comment_key = ndb.Key(urlsafe=comment_del_key_url)
                        comment = comment_key.get()
                        if comment.user_id == user_id:
                            comment_key.delete()
                            time.sleep(0.1)
                            self.redirect("/blog/entry?entry=%s" % entry_key_url)
                        else:
                            self.render("entry.html", entry=entry, login=login_text,
                                        logout=logout_text,
                                        error="You are not allowed to delete the comment")
                    else:
                        comment_key = ndb.Key(urlsafe=comment_edit_key_url)
                        comment = comment_key.get()
                        if comment.user_id == user_id:
                            self.redirect("/blog/entry/comment?entry=" + entry_key_url +
                                          "&comment=" + comment_edit_key_url)
                        else:
                            self.render("entry.html", entry=entry, login=login_text,
                                        logout=logout_text,
                                        error="You are not allowed to edit the comment")
                else:
                    entry_id = entry_key.id()
                    content = self.request.get("content")
                    if content and entry_key:
                        comment = Comment(content=content, entry_id=entry_id, user_id=user_id)
                        comment.put()
                        time.sleep(0.1)
                        self.redirect("/blog/entry?entry=%s" % entry_key_url)
            else:
                login_text = "Log In"
                logout_text = None
                self.render("entry.html", entry=entry, login=login_text,
                            logout=logout_text, error="You must be login first")
        else:
            self.error(404)
            return
