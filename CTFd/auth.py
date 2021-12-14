import base64

import requests
from flask import Blueprint, abort
from flask import current_app as app
from flask import redirect, render_template, request, session, url_for
from itsdangerous.exc import BadSignature, BadTimeSignature, SignatureExpired

from CTFd.cache import clear_team_session, clear_user_session
from CTFd.models import Teams, UserFieldEntries, UserFields, Users, db
from CTFd.utils import config, email, get_app_config, get_config
from CTFd.utils import user as current_user
from CTFd.utils import validators
from CTFd.utils.config import is_teams_mode
from CTFd.utils.config.integrations import mlc_registration
from CTFd.utils.config.visibility import registration_visible
from CTFd.utils.crypto import verify_password
from CTFd.utils.decorators import ratelimit
from CTFd.utils.decorators.visibility import check_registration_visibility
from CTFd.utils.helpers import error_for, get_errors, markup
from CTFd.utils.logging import log
from CTFd.utils.modes import TEAMS_MODE
from CTFd.utils.security.auth import login_user, logout_user
from CTFd.utils.security.signing import unserialize
from CTFd.utils.validators import ValidationError

auth = Blueprint("auth", __name__)


@auth.route("/confirm", methods=["POST", "GET"])
@auth.route("/confirm/<data>", methods=["POST", "GET"])
@ratelimit(method="POST", limit=10, interval=60)
def confirm(data=None):
    return redirect(url_for("views.static_html"))


@auth.route("/reset_password", methods=["POST", "GET"])
@auth.route("/reset_password/<data>", methods=["POST", "GET"])
@ratelimit(method="POST", limit=10, interval=60)
def reset_password(data=None):
    return redirect(url_for("views.static_html"))


@auth.route("/register", methods=["POST", "GET"])
@check_registration_visibility
@ratelimit(method="POST", limit=10, interval=5)
def register():
    return redirect(url_for("views.static_html"))


@auth.route("/login", methods=["POST", "GET"])
@ratelimit(method="POST", limit=10, interval=5)
def login():
    return redirect(url_for("views.static_html"))


@auth.route("/oauth")
def oauth_login():
    return redirect(url_for("views.static_html"))


@auth.route("/redirect", methods=["GET"])
@ratelimit(method="GET", limit=10, interval=60)
def oauth_redirect():
    return redirect(url_for("views.static_html"))


@auth.route("/logout")
def logout():
    if current_user.authed():
        logout_user()
    return redirect(url_for("views.static_html"))
