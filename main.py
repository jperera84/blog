""" App-Rot Web Application"""
import os
import re
import random
import string
import hashlib
import time
import webapp2
import jinja2

from google.appengine.ext import ndb

TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), 'templates')
JINJA_ENV = jinja2.Environment(loader=jinja2.FileSystemLoader(TEMPLATE_DIR), autoescape=True)

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

def validate_username(username):
    """ Method validate username """
    match = re.match(r"^[a-zA-Z0-9_-]{3,20}$", username)
    if match:
        return ""
    else:
        return "Username invalid!"

def validate_password(password):
    """ Method validate username """
    match = re.match(r"^.{3,20}$", password)
    if match:
        return ""
    else:
        return "Password invalid!"

def validate_verify(password, verify):
    """ Method validate username """
    if password:
        if password == verify:
            return ""
        else:
            return "Password didn't match!"
    else:
        return ""

def validate_email(email):
    """ Method validate username """
    if email:
        match = re.match(r"^[\S]+@[\S]+.[\S]+$", email)
        if match:
            return ""
        else:
            return "Email invalid!"
    else:
        return ""

def make_salt():
    """ Generate a salt string """
    return ''.join(random.choice(string.letters) for x in range(5))

def make_pw_hash(name, password, salt=None):
    """ Generate the hash password """
    if not salt:
        salt = make_salt()
    hash_pass = hashlib.sha256(name + password + salt).hexdigest()
    return '%s|%s' % (hash_pass, salt)

class Entry(ndb.Model):
    """ Entry class """
    subject = ndb.StringProperty(required=True)
    content = ndb.TextProperty(required=True)
    created = ndb.DateTimeProperty(auto_now_add=True)
    user_id = ndb.IntegerProperty(required=True)
    like = ndb.BooleanProperty()
    def render(self):
        """ Render the blog content """
        _render_text = self.content.replace('\n', '<br>')
        return _render_text
    def query_comments(self):
        """ Return comments from entry """
        aux_id = self.key.id()
        comments = Comment.query(Comment.entry_id == aux_id).order(-Comment.last_modified).fetch(10)
        return comments


class Comment(ndb.Model):
    """ Comment class """
    content = ndb.TextProperty(required=True)
    created = ndb.DateTimeProperty(auto_now_add=True)
    entry_id = ndb.IntegerProperty(required=True)
    user_id = ndb.IntegerProperty(required=True)
    last_modified = ndb.DateTimeProperty(auto_now=True)

class User(ndb.Model):
    """ User class"""
    username = ndb.StringProperty(required=True)
    password = ndb.StringProperty(required=True)
    email = ndb.StringProperty()
    registered = ndb.DateTimeProperty(auto_now_add=True)

class EntryUserLikes(ndb.Model):
    """ EntryUserLikes class"""
    created = ndb.DateTimeProperty(auto_now_add=True)
    entry_id = ndb.IntegerProperty(required=True)
    user_id = ndb.IntegerProperty(required=True)

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

class NewPost(Handler):
    """ NewPost Handler class"""
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
            del_att = self.request.get("del")
            if key_url and not del_att:
                post = ndb.Key(urlsafe=key_url).get()
                self.render_form(login=login_text, logout=logout_text, subject=post.subject,
                                content=post.content, key=key_url)
            else:
                if del_att and key_url:
                    post = ndb.Key(urlsafe=key_url).get()
                    if post.user_id == user.key.id():
                        post.key.delete()
                        self.redirect("/blog")
                    else:
                        self.render("newpost.html",
                                    content_error="You are not allowed to delete this post")
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

class CommentHandler(Handler):
    """Comment Handler class"""
    def get(self):
        """ Default get method """
        user_url = self.request.cookies.get('user_key', None)
        login_text = "Log In"
        logout_text = None
        if user_url:
            user = ndb.Key(urlsafe=user_url).get()
            login_text = "Welcome %s" % user.username
            logout_text = "Logout"
            comment_edit_key_url = self.request.get("comment")
            entry_key_url = self.request.get("entry")
            comment_key = ndb.Key(urlsafe=comment_edit_key_url)
            comment = comment_key.get()
            self.render("comment.html", login=login_text,
                        logout=logout_text, entry_key=entry_key_url,
                        comment_key=comment_edit_key_url,
                        comment=comment.content)
        else:
            self.render("comment.html", login=login_text,
                        logout=logout_text, error="You must be login First")
    def post(self):
        """ Post method to handle modify comments """
        user_url = self.request.cookies.get('user_key', None)
        if user_url:
            comment_edit_key_url = self.request.get("comment_key")
            comment_key = ndb.Key(urlsafe=comment_edit_key_url)
            entry_key_url = self.request.get("entry_key")
            comment = comment_key.get()
            content = self.request.get('content')
            comment.content = content
            comment.put()
            time.sleep(0.1)
            self.redirect("/blog/entry?entry=%s" % entry_key_url)


class EntryHandler(Handler):
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
    def post(self):
        """ Post method that handle add, delete or modify comments """
        entry_key_url = self.request.get("entry_key")
        entry_key = ndb.Key(urlsafe=entry_key_url)
        entry = ndb.Key(urlsafe=entry_key_url).get()
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
                    self.redirect("/blog/entry/comment?entry=" + entry_key_url +
                                  "&comment=" + comment_edit_key_url)
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

class SignUp(Handler):
    """ Main Program class"""
    def get(self):
        """ Default get method"""
        self.render("signup.html")
    def post(self):
        """ Post method to register a new user """
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')
        if username:
            query = User.query(User.username == username).fetch(1)
            user = None
            if query:
                user = query[0]
            if user:
                self.render("signup.html", emailError="The user already exist.")
            else:
                username_error = validate_username(username)
                password_error = validate_password(password)
                verify_error = validate_verify(password, verify)
                email_error = validate_email(email)
                if username_error or password_error or verify_error or email_error:
                    self.render("signup.html", username=username, usernameError=username_error,
                                passwordError=password_error, verifyError=verify_error, email=email,
                                emailError=email_error)
                else:
                    user = User(username=username, password=make_pw_hash(username, password),
                                email=email)
                    user_key = user.put()
                    user_url = user_key.urlsafe()
                    self.response.headers.add_header('Set-Cookie', 'user_key = %s' % user_url,
                                                     path='/')
                    self.redirect("/blog/welcome")
        else:
            self.render("signup.html", usernameError="The username can't be empty")

class Welcome(Handler):
    """ Welcome handler class """
    def get(self):
        """ Default get method"""
        user_url = self.request.cookies.get('user_key', None)
        if user_url:
            user = ndb.Key(urlsafe=user_url).get()
            self.render("welcome.html", login="Login", username=user.username)
        else:
            self.redirect("/blog/signup")

class Login(Handler):
    """ Login handler class """
    def get(self):
        """ Default get method """
        user_url = self.request.cookies.get('user_key', None)
        if user_url:
            self.redirect("/blog")
        else:
            self.render("login.html", login="Login")
    def post(self):
        """ Post method to verify username and password"""
        username = self.request.get('username')
        password = self.request.get('password')
        query = User.query(User.username == username).fetch(1)
        user = None
        if query:
            user = query[0]
        if user:
            salt = user.password.split('|')[1]
            if user.password == make_pw_hash(username, password, salt):
                user_url = user.key.urlsafe()
                self.response.headers.add_header('Set-Cookie', 'user_key = %s' % user_url, path='/')
                self.redirect("/blog")
            else:
                error = "The username or password is incorrect!"
                self.render("login.html", login="Login", username=username, error=error)
        else:
            error = "The username not exists!"
            self.render("login.html", login="Login", username=username, error=error)

class Logout(Handler):
    """ Logout handler class """
    def get(self):
        """ Default get method"""
        user_url = self.request.cookies.get('user_key', None)
        if user_url:
            self.response.delete_cookie('user_key', path='/blog')
            self.redirect("/blog/login")
        else:
            self.redirect("/blog/login")


APP = webapp2.WSGIApplication([
    ('/blog', MainPage),
    ('/blog/newpost', NewPost),
    ('/blog/entry/comment', CommentHandler),
    ('/blog/entry', EntryHandler),
    ('/blog/signup', SignUp),
    ('/blog/welcome', Welcome),
    ('/blog/login', Login),
    ('/blog/logout', Logout)], debug=True)
    