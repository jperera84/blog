""" App-Blog Web Application"""
import time
import webapp2
import jinja2
from google.appengine.ext import ndb
from models.entry import Entry
from models.entryuserlikes import EntryUserLikes
from handlers.handler import Handler
from handlers.entrylike import EntryLike
from handlers.signup import SignUp
from handlers.entryhandler import EntryHandler
from handlers.commenthandler import CommentHandler
from handlers.entryview import EntryView
from handlers.login import Login
from handlers.welcome import Welcome
from handlers.logout import Logout
from handlers.commentaddhandler import CommentAddHandler

class MainPage(Handler):
    """ Main Program class"""
    def get(self):
        """ Default get method"""
        login_text = "Log In"
        logout_text = None
        user_url = self.request.cookies.get('user_key', None)
        entries = Entry.query().order(-Entry.created).fetch(10)
        entries_aux = []
        if user_url:
            user = ndb.Key(urlsafe=user_url).get()
            login_text = "Welcome %s" % user.username
            logout_text = "Logout"
            for entry in entries:
                entry.like = EntryUserLikes.query(EntryUserLikes.user_id == user.key.id(), EntryUserLikes.entry_id == entry.key.id()).get() != None or False
                entries_aux.append(entry)
        else:
            for entry in entries:
                entry.like = False
                entries_aux.append(entry)
        self.render("index.html", login=login_text, entries=entries_aux, logout=logout_text)


APP = webapp2.WSGIApplication([
    ('/blog', MainPage),
    ('/blog/entrylike', EntryLike),
    ('/blog/newpost', EntryHandler),
    ('/blog/comment', CommentAddHandler),
    ('/blog/entry/comment', CommentHandler),
    ('/blog/entry', EntryView),
    ('/blog/signup', SignUp),
    ('/blog/welcome', Welcome),
    ('/blog/login', Login),
    ('/blog/logout', Logout)], debug=True)
