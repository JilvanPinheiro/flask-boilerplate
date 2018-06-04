# -*- coding: utf-8 -*-
from base_service import BaseService
from flask import request, abort
from business.user_business import UserBusiness


class UserService(BaseService):
    def cancel_invite(self, invitation_id):
        try:
            # get logged user
            loggedUser = self.get_logged_user()

            # prepare invite to be canceled
            invite = {
                'id': invitation_id
            }

            userSrv = UserBusiness()
            userSrv.cancel_invite(invite, loggedUser)

            return self.return_success('Convite cancelado com sucesso.', None)
        except Exception as ex:
            return self.return_exception(ex)

    def get(self, user_id):
        try:
            # get logged user
            loggedUser = self.get_logged_user()

            # prepare user to be retrieved
            user = {
                'id': user_id
            }

            # get and return users
            userSrv = UserBusiness()
            user = userSrv.get(user, loggedUser)

            return self.return_success('Usuário retornado com sucesso.', user)
        except Exception as ex:
            return self.return_exception(ex)

    def invite(self):
        try:
            # get logged user
            loggedUser = self.get_logged_user()

            # prepare user to be invited
            profileId = None
            if request.json.get('profile'): #error:  AttributeError: 'NoneType' object has no attribute 'get'
                profileId = request.json.get('profile')['id']

            supervisor_id = None
            if request.json.get('supervisor'):
                supervisor_id = request.json.get('supervisor')['id']

            user = {
                'profile': {
                    'id': profileId
                },
                'full_name': request.json.get('full_name'),
                'email': request.json.get('email'),
                'company': loggedUser['company'] if loggedUser else None,
                'answers': request.json.get('answers'),
                'supervisor': {
                    'id': supervisor_id
                }
            }

            userSrv = UserBusiness()
            invited_user = userSrv.invite(user, loggedUser)

            return self.return_success('Convite enviado com sucesso.', invited_user)
        except Exception as ex:
            return self.return_exception(ex)

    def refresh_invite(self, user_id):
        try:
            # get logged user
            loggedUser = self.get_logged_user()


            # prepare parameters
            user = {
                'id': user_id
            }

            # refresh user invite
            userBus = UserBusiness()
            invited_user = userBus.refresh_invite(user, loggedUser)

            return self.return_success('Convite enviado com sucesso.', None)
        except Exception as ex:
            return self.return_exception(ex)

    def list(self):
        try:
            # get logged user
            loggedUser = self.get_logged_user()

            # get and return users
            userSrv = UserBusiness()
            users = userSrv.list(loggedUser)

            return self.return_success('Usuários listados com sucesso.', users)
        except Exception as ex:
            return self.return_exception(ex)

    def login(self):
        try:
            credentials = {
                'email': request.json.get('email'),
                'password': request.json.get('password')
            }

            userSrv = UserBusiness()
            login_stuff = userSrv.login(credentials)

            return self.return_success('Login realizado com sucesso.', login_stuff)
        except Exception as ex:
            return self.return_exception(ex)

    def logout(self):
        try:
            token = {
                'code': request.json.get('token')
            }

            userSrv = UserBusiness()
            userSrv.logout(token)

            return self.return_success('Logout realizado com sucesso.', None)
        except Exception as ex:
            return self.return_exception(ex)

    def request_reset_password(self):
        try:
            credentials = {
                'email': request.json.get('email')
            }

            userSrv = UserBusiness()
            request_reset = userSrv.request_reset_password(credentials)

            return self.return_success(
                'Um e-mail foi enviado para ' + str(credentials['email']) + ' com mais instruções.', None)
        except Exception as ex:
            return self.return_exception(ex)

    def reset_password(self, user_id=None):
        try:
            # prepare parameter according to the type of request
            parameters = None
            if not user_id:
                # user will reset its own passowrd
                reset_request = {
                    'token': request.json.get('token'),
                    'email': request.json.get('email'),
                    'new_password': request.json.get('new_password'),
                    'new_password_confirmation': request.json.get('new_password_confirmation')
                }

                userSrv = UserBusiness()
                userSrv.reset_own_password(reset_request)
            else:
                # get logged user
                logged_user = self.get_logged_user()

                # user will reset other user's password
                reset_request = {
                    'user': {
                        'id': user_id
                    },
                    'new_password': request.json.get('new_password'),
                    'new_password_confirmation': request.json.get('new_password_confirmation')
                }
                userSrv = UserBusiness()
                userSrv.reset_password(reset_request, logged_user)

            return self.return_success('Senha reinicializada com sucesso.', None)
        except Exception as ex:
            return self.return_exception(ex)

    def self_update(self):
        try:
            user = {
                'full_name': request.json.get('full_name'),
                'email': request.json.get('email'),
                'new_password': request.json.get('new_password'),
                'new_password_confirmation': request.json.get('new_password_confirmation')
            }

            # get logged user
            loggedUser = self.get_logged_user()

            userSrv = UserBusiness()
            updated_user = userSrv.self_update(user, loggedUser)

            return self.return_success('Alterações realizadas com sucesso.', updated_user)
        except Exception as ex:
            return self.return_exception(ex)

    def signup(self):
        try:
            user = {
                'email': request.json.get('email'),
                'access_code': request.json.get('access_code'),
                'password': request.json.get('password'),
                'password_confirmation': request.json.get('password_confirmation')
            }

            userSrv = UserBusiness()
            logged_user = userSrv.signup(user)

            return self.return_success('Cadastro realizado com sucesso.', logged_user)
        except Exception as ex:
            return self.return_exception(ex)

    def update(self, user_id):
        try:
            statusId = None
            if request.json.get('status'):
                statusId = request.json.get('status')['id']

            profileId = None
            if request.json.get('profile'):
                profileId = request.json.get('profile')['id']

            supervisor_id = None
            if request.json.get('supervisor'):
                supervisor_id = request.json.get('supervisor')['id']

            user = {
                'id': user_id,
                'status': {
                    'id': statusId
                },
                'profile': {
                    'id': profileId
                },
                'full_name': request.json.get('full_name'),
                'email': request.json.get('email'),
                'new_password': request.json.get('new_password'),
                'new_password_confirmation': request.json.get('new_password_confirmation'),
                'current_password': request.json.get('current_password'),
                'supervisor': {
                    'id': supervisor_id
                }
            }

            # get logged user
            loggedUser = self.get_logged_user()

            userSrv = UserBusiness()
            userSrv.update(user, loggedUser)

            return self.return_success('Alterações realizadas com sucesso.', None)
        except Exception as ex:
            return self.return_exception(ex)

    def validate_token(self, email, code):
        try:
            token = {
                'code': code,
                'user': {
                    'email': email
                }
            }

            userSrv = UserBusiness()
            token_validation = userSrv.validate_token(token)
            validation_return = {
                'is_valid': token_validation
            }

            return self.return_success('Validação de token realizada com sucesso.', validation_return)
        except Exception as ex:
            return self.return_exception(ex)
