""" Entry Handler """
import webapp2
import jinja2
from handlers.handler import Handler
from models.entry import Entry
from google.appengine.ext import ndb

def validate_subject(subject):
    """ Validate Subject"""
    if subject:
        return ""
    else:
        return "The subject can't be empty!"

def validate_content(content):
    """ Validate Content"""
    if content:
        return ""
    else:
        return "The content can't be empty!"

class EntryHandler(Handler):
    """ EntryHandler Handler class"""
    def render_form(self, login="", logout="", subject="",
                    subject_error="", content="", content_error="", key=""):
        """ Default render method"""
        self.render("newpost.html", login=login, logout=logout, subject=subject,
                    subject_error=subject_error, content=content, content_error=content_error,
                    key=key)

    def get(self):
        """ Default get method"""
        user_url = self.request.cookies.get('user_key', None)
        login_text = "Log In"
        logout_text = None
        if user_url:
            user = ndb.Key(urlsafe=user_url).get()
            login_text = "Welcome %s" % user.username
            logout_text = "Logout"
            key_url = self.request.get("key")
            if key_url:
                post = ndb.Key(urlsafe=key_url).get()
                if post:
                    if post.user_id != user.key.id():
                        self.render("newpost.html",
                                    content_error="You are not allowed to delete this post")
            del_att = self.request.get("del")
            if key_url and not del_att:
                if post:
                    self.render_form(login=login_text, logout=logout_text, subject=post.subject,
                                     content=post.content, key=key_url)
                else:
                    self.error(404)
                    return
            else:
                if del_att and key_url:
                    if post:
                        if post.user_id == user.key.id():
                            post.key.delete()
                            self.redirect("/blog")
                        else:
                            self.render("newpost.html",
                                        content_error="You are not allowed to delete this post")
                    else:
                        self.error(404)
                        return
                else:
                    self.render_form(login=login_text, logout=logout_text)
        else:
            self.redirect("/blog/login")

    def post(self):
        """ Post method that handle Add or Edit entries """
        user_url = self.request.cookies.get('user_key', None)
        if user_url:
            user = ndb.Key(urlsafe=user_url).get()
            key_url = self.request.get("key")
            if key_url:
                post = ndb.Key(urlsafe=key_url).get()
                if post:
                    subject = self.request.get("subject")
                    content = self.request.get("content")
                    subject_error = validate_subject(subject)
                    content_error = validate_content(content)
                    if not subject_error or not content_error:
                        if post.user_id == user.key.id():
                            post.subject = subject
                            post.content = content
                            post.like = False
                            post.put()
                            self.redirect("/blog/entry?entry=%s" % key_url)
                        else:
                            self.render("newpost.html",
                                        content_error="You are not allowed to Edit this post")
                else:
                    self.error(404)
                    return
            else:
                subject = self.request.get("subject")
                content = self.request.get("content")
                subject_error = validate_subject(subject)
                content_error = validate_content(content)
                if subject_error or content_error:
                    self.render("newpost.html", subject=subject, subject_error=subject_error,
                                content=content, content_error=content_error)
                else:
                    entry = Entry(subject=subject, content=content,
                                  user_id=user.key.id(), like=False)
                    entry_key = entry.put()
                    entry_url = entry_key.urlsafe()
                    self.redirect("/blog/entry?entry=%s" % entry_url)
        else:
            self.render("newpost.html", login="Log In", subject="", subject_error="",
                        content="", content_error="You must be login first")
