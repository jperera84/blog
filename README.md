# BLOG WEB TECHNOLOGIES WEBSITE

Backend project FullStack Web Developer Nanodegree

This project was built as final project for the module Back End for the FullStack Web Developer Nanodegree (UDACITY).

The project is hosted in Google App Engine: https://blog-app-160801.appspot.com/blog 

# How to use the website?

Users can Register in the website using the link Login/Register, is simple to create a new user in the website only has to
enter the user, password, confirm the password and optionally the email.

Once the user is register all the functionalities are available to being use:
  1. Manage entries. (Create, edit or delete entries) For this the website verify is the entry was create by the user, so you are not going to be able to change an entry created by other registered user.
  2. Users can enter comments in the entries. Also the users can Edit or delete the comments.
  3. Users are allowed to mark the entries they like clicking in the Star icon on the entry list and if the user click again could unmark the entry.
  4. Users can logout from the website.
  
# How to run the website.

Anyone could download or clone the repository and edit the project.

The project was developed using Python 2.7, Jinja2 Framework and Google Appengine. To store the data for the website it is being used
Google Datastore and the python library NDB `from google.appengine.ext import ndb`

To run the project users can use the command: `dev_appserver.py .` to initialize a local web server, and after the changes are made
the project clould be upload to the Google Cloud Platform.
  
