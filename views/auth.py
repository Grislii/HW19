"""
POST /auth — получает логин и пароль из Body запроса в виде JSON,
далее проверяет соотвествие с данными в БД (есть ли такой пользователь,
такой ли у него пароль)
и если всё оk — генерит пару access_token и refresh_token и
отдает их в виде JSON.
"""
from flask import request, abort
from flask_restx import Namespace, Resource

from dao.model.user import User
from implemented import auth_service
from setup_db import db

auth_ns = Namespace('auth')

@auth_ns.route("/")
class AuthView(Resource):
    def post(self):
        req_json = request.json
        username = req_json.get("username")
        password = req_json.get("password")
        if None in [username, password]:
            abort(400)

        # user = db.session.query(User).filter(User.username == username).first()
        tokens = auth_service.generate_tokens(username, password)
        if tokens:
            return auth_service.generate_tokens(username, password)
        else:
            return "Ошибка в запросе", 400
        return # tokens

    def put(self):
        req_json = request.json
        refresh_token = req_json.get("refresh_token")

        if not refresh_token:
            return "Не задан токен", 400

        tokens = auth_service.approve_refresh_token(refresh_token)

        if tokens:
            return tokens