import os.path
from functools import wraps

from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor, CKEditorField
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import *
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager(app)
gravatar = Gravatar(app, size=100, rating='g', force_default=False, default='retro', force_lower=False, use_ssl=False, base_url=None)


def admin_only(f):
    @wraps(f)
    def function(*args, **kwargs):
        if current_user.is_anonymous or current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)

    return function


@login_manager.user_loader
def user(user_id):
    return User.query.get(int(user_id))


# CONFIGURE TABLES
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = Column(Integer, primary_key=True)
    author_id = Column(Integer, ForeignKey('User.id'))
    title = Column(String(250), unique=True, nullable=False)
    subtitle = Column(String(250), nullable=False)
    date = Column(String(250), nullable=False)
    body = Column(Text, nullable=False)
    img_url = Column(String(250), nullable=False)
    author = relationship("User", back_populates="posts")
    comment = relationship("Comment", back_populates="parent_post")


class User(UserMixin, db.Model):
    __tablename__ = "User"
    id = Column(Integer, primary_key=True)
    email = Column(String(250), nullable=False, unique=True)
    password = Column(String(250), nullable=False)
    name = Column(String(250), nullable=False)
    posts = relationship('BlogPost', back_populates="author")
    comment = relationship('Comment', back_populates="author")


class Comment(db.Model):
    __tablename__ = "comments"
    id = Column(Integer, primary_key=True)
    text = Column(String, nullable=False)
    author_id = Column(Integer, ForeignKey('User.id'))
    post_id = Column(Integer, ForeignKey('blog_posts.id'))
    author = relationship("User", back_populates="comment")
    parent_post = relationship("BlogPost", back_populates="comment")


if not os.path.exists('sqlite:///blog.db'):
    db.create_all()


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=["POST", "GET"])
def register():
    form = RegisterForm()
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        name = request.form["username"]
        print(email, password, name)
        if form.validate_on_submit():
            try:
                new_user = User(email=email, password=generate_password_hash(password=password, salt_length=8),
                                name=name)
                db.session.add(new_user)
                db.session.commit()
            except:
                flash("You've already signed up with that email. try Logg in instead")
                return render_template('register.html', form=form)
            else:
                login_user(new_user)
                return redirect(url_for('get_all_posts'))

    return render_template("register.html", form=form)


@app.route('/login', methods=["POST", "GET"])
def login():
    form = LoginForm()
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        try:
            user_now = User.query.filter_by(email=email).first()
            pswd = user_now.password
        except:
            flash("That email doesn't exist please try again")
        else:
            if check_password_hash(pwhash=pswd, password=password):
                login_user(user_now)
                return redirect(url_for('get_all_posts'))
            else:
                flash('Password incorrect please try again')
                return render_template("login.html", form=form)
    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["POST", "GET"])
def show_post(post_id):
    form = CommentForm()
    requested_post = BlogPost.query.get(post_id)
    all_comments = requested_post.comment
    if request.method == "POST":
        if current_user.is_authenticated:
            if form.validate_on_submit():
                comment = request.form["text"]
                print(comment)
                new_comment = Comment(text=comment,
                                      author_id=current_user.id,
                                      post_id=post_id
                                      )
                db.session.add(new_comment)
                db.session.commit()
                form.text.data = ""
                return redirect(f'/post/{post_id}')
        else:
            flash(message="You need to login or register to comment")
            return redirect('/login')
    return render_template("post.html", post=requested_post, form=form,  comments=all_comments)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["POST", "GET"])
@login_required
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            author_id=current_user.id,
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            date=date.today().strftime("%B %d, %Y")
        )
        print(new_post)
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=["POST", "GET"])
@admin_only
def edit_post(post_id):
    # post_id = request.args.get("id")
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):

    # post_id = request.args.get("id")
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='192.168.0.107', debug=True)
