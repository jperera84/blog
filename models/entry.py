""" Entity Model Class Entry """
from comment import Comment
from google.appengine.ext import ndb

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
