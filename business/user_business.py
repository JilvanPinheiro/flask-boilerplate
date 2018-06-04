# -*- coding: utf-8 -*-
from base_business import BaseBusiness
from email_business import EmailBusiness
from config import Server
from constants import *
from framework.util import *
from framework.exception.exceptions import *
from repositories.password_reset_request_repository import PasswordResetRequestRepository
from repositories.permission_repository import PermissionRepository
from repositories.user_invite_repository import UserInviteRepository
from repositories.user_repository import UserRepository
from repositories.token_repository import TokenRepository

import uuid
from passlib.hash import pbkdf2_sha256


class UserBusiness(BaseBusiness):
    def cancel_invite(self, invite, loggedUser):
        if not loggedUser:
            raise NotAuthenticatedException(
                'Você precisa estar logado para cancelar um convite. Efetue o login na plataforma.')

        # prepare context
        self.initialize_context()
        self.context.connect_cockpit()

        # check permission if user has permission to invite other users
        permRep = PermissionRepository(self.context)
        permission = permRep.get({'user': {'id': loggedUser['id']}, 'action': Permission.USERS_INVITE})
        if not permission:
            raise NotAuthorizedException(
                'Você não possui permissão para convidar outros usuários ou cancelar convites.')

        # validate required fields
        exceptions = []
        if (not invite.get('id', None)):
            raise RequiredFieldException('É necessário informar o ID do convite.', 'id')

        # cancel invite
        userInviteRep = UserInviteRepository(self.context)
        invite['status'] = {
            'id': Status.DELETED
        }
        userInviteRep.update_status(invite)

        # finalize context
        self.close_and_commit_context()

    def get(self, user, logged_user):
        if not logged_user:
            raise NotAuthenticatedException(
                'Você precisa estar logado para recuperar os dados de um usuário. Efetue o login na plataforma.')

        # prepare context
        self.initialize_context()
        self.context.connect_cockpit()
        self.context.connect_cockpit_nosql()

        # validate required fields
        if (not user.get('id', None)):
            raise RequiredFieldException('É necessário informar o código do usuário.', 'id')

        # check permission if user has permission to list all users
        if logged_user['id'] != user['id']:
            permRep = PermissionRepository(self.context)
            permission = permRep.get({'user': {'id': logged_user['id']}, 'action': Permission.USERS_UPDATE})
            if not permission:
                raise NotAuthorizedException('Você não possui permissão para gerir os usuários.')

        # get user
        userRep = UserRepository(self.context)
        return_user = userRep.get(user)

        # get user invite
        user_invite_rep = UserInviteRepository(self.context)
        user_invite = user_invite_rep.get_last_invite(return_user)
        if user_invite:
            if user_invite['status']['id'] == Status.DELETED:
                user_invite['status']['description'] = 'Convite cancelado'
            elif user_invite['has_expired'] == True:
                user_invite['status']['description'] = 'Convite expirou'
            else:
                user_invite['status']['description'] = 'Aguardando aceite'
            return_user['invite'] = user_invite
        else:
            return_user['invite'] = None

        # finalize context
        self.close_and_commit_context()

        return return_user

    def get_by_valid_token(self, token):
        # prepare context
        self.initialize_context()
        self.context.connect_cockpit()

        # get user
        userRep = UserRepository(self.context)
        loadedUser = userRep.get_by_valid_token(token)

        # finalize context
        self.close_and_commit_context()

        return loadedUser

    def invite(self, user, loggedUser):
        if not loggedUser:
            raise NotAuthenticatedException(
                'Você precisa estar logado para convidar outros usuários. Efetue o login na plataforma.')

        # prepare context
        self.initialize_context()
        self.context.connect_cockpit()

        # check permission if user has permission to invite other users
        permRep = PermissionRepository(self.context)
        permission = permRep.get({'user': {'id': loggedUser['id']}, 'action': Permission.USERS_INVITE})
        if not permission:
            raise NotAuthorizedException('Você não possui permissão para convidar outros usuários.')

        # validate required fields
        exceptions = []
        if (not user.get('email', None)):
            exceptions.append(RequiredFieldException('É necessário informar o e-mail.', 'email'))
        elif (not validate_emaill(user['email'])):
            exceptions.append(RequiredFieldException('E-mail inválido.', 'email'))
        if (not user.get('full_name', None)):
            exceptions.append(RequiredFieldException('É necessário informar o nome completo.', 'full_name'))
        if (not user.get('profile', None) or not user['profile'].get('id', None)):
            exceptions.append(RequiredFieldException('É necessário informar o perfil do usuário.', 'profile.id'))

        if (not exceptions):
            # check if user exists
            userRep = UserRepository(self.context)
            userInviteRep = UserInviteRepository(self.context)
            loadedUser = userRep.get_by_email(user)
            if loadedUser:
                if loadedUser['status']['id'] == UserStatus.DELETED:
                    # check if there is an answer for this issue
                    if not user['answers'] or not user['answers'].get('user_has_been_deleted', None):
                        raise BusinessException(
                            'Este usuário já foi convidado e posteriormente excluído da plataforma. Deseja reativa-lo?',
                            {'issue': 'user_has_been_deleted'})
                elif loadedUser['status']['id'] == UserStatus.SUSPENDED_BY_STAFF:
                    # check if there is an answer for this issue
                    if not user['answers'] or not user['answers'].get('user_has_been_suspended', None):
                        raise BusinessException(
                            'Este usuário já foi convidado e posteriormente seu acesso foi suspenso pelos administradores da plataforma. Deseja reativa-lo?',
                            {'issue': 'user_has_been_suspended'})
                elif loadedUser['status']['id'] == UserStatus.INVITED:
                    # check user invite
                    userInvite = userInviteRep.get_last_invite(loadedUser)
                    if userInvite['status']['id'] == Status.DELETED:
                        # check if there is an answer for this issue
                        if not user['answers'] or not user['answers'].get('invite_has_been_canceled', None):
                            raise BusinessException(
                                'Este usuário já foi convidado anteriormente, mas o convite foi cancelado pela equipe de administradores da plataforma antes que ele completasse seu cadastro. Deseja enviar um novo convite?',
                                {'issue': 'invite_has_been_canceled'})
                    elif userInvite['has_expired'] == True:
                        # check if there is an answer for this issue
                        if not user['answers'] or not user['answers'].get('invite_has_expired', None):
                            raise BusinessException(
                                'Este usuário já foi convidado anteriormente, mas o convite expirou. Deseja enviar um novo convite?',
                                {'issue': 'invite_has_expired'})
                    else:
                        # check if there is an answer for this issue
                        if not user['answers'] or not user['answers'].get('user_has_already_been_invited', None): ######### EXCEÇÃO NAO ESTA CHEGANDO
                            raise BusinessException(
                                'Este usuário já foi convidado anteriormente, mas ainda não completou seu cadastro. Deseja enviar um novo convite?',
                                {'issue': 'user_has_already_been_invited'})
            else:
                # insert
                user['status'] = {
                    'id': UserStatus.INVITED
                }
                userId = userRep.insert(user)
                user['id'] = userId

                # set user permissions
                self.set_user_permissions(user)

                # insert user invite
                temporary_access_code = str(uuid.uuid4())[0: 6].upper()
                userInvite = {
                    'user': {
                        'id': userId
                    },
                    'access_code': temporary_access_code,
                    'status': {
                        'id': Status.ACTIVE
                    },
                    'user_created': loggedUser
                }
                userInviteRep.insert(userInvite)

                # prepare url to reset password
                url = Server.URL + 'signup'

                # send e-mail
                email = {
                    'to': user['email'],
                    'subject': 'Acesso à plataforma RisKnow',
                    'body': 'Olá! <br><br> Você foi convidado a se cadastrar na plataforma RisKnow. <br><br><a href="' + url + '">Clique aqui</a> para dar continuidade ao processo de cadastro e definir uma senha de acesso. <br>Quando solicitado, informe o código: <b>' + temporary_access_code + '</b><br><br>Atenciosamente,<br><b>Equipe RisKnow</b>'
                }
                emailBusiness = EmailBusiness(self.context)
                emailBusiness.send(email)

                # finalize context
                self.close_and_commit_context()

                return {
                    'email': user['email'],
                    'access_code': userInvite['access_code']
                }
        else:
            raise ManyExceptionsException(exceptions)

    def list(self, logged_user):
        if not logged_user:
            raise NotAuthenticatedException(
                'Você precisa estar logado para listar os usuários. Efetue o login na plataforma.')

        # prepare context
        self.initialize_context()
        self.context.connect_cockpit()
        self.context.connect_cockpit_nosql()

        # check permission if user has permission to list all users
        permRep = PermissionRepository(self.context)
        permission = permRep.get({'user': {'id': logged_user['id']}, 'action': Permission.USERS_UPDATE})
        if not permission:
            raise NotAuthorizedException('Você não possui permissão para gerir os usuários.')

        # list users
        userRep = UserRepository(self.context)
        users = userRep.list_by_company(logged_user['company'])

        # finalize context
        self.close_and_commit_context()

        return users

    def create_user_hash_password(self, password):
        return pbkdf2_sha256.encrypt(password, rounds=200000, salt_size=16)

    # Login user according to email and password.
    def login(self, credentials):
        # validate required fields
        exceptions = []
        if (not credentials['email']):
            exceptions.append(RequiredFieldException('É necessário informar seu e-mail.', 'email'))
        elif (not validate_emaill(credentials['email'])):
            exceptions.append(RequiredFieldException('E-mail inválido.', 'email'))
        if (not credentials['password']):
            exceptions.append(RequiredFieldException('É necessário informar sua senha.', 'password'))

        if (not exceptions):
            # prepare context
            self.initialize_context()
            self.context.connect_cockpit()

            userRep = UserRepository(self.context)

            user = userRep.get_by_email(credentials)
            if user:
                if user['status']['id'] == UserStatus.DELETED:
                    raise BusinessException(
                        'Este usuário está desativado. Entre em contato com o administrador da plataforma para maiores informações.')
                elif user['status']['id'] == UserStatus.SUSPENDED_BY_STAFF:
                    raise BusinessException(
                        'Este usuário foi suspenso pelo suporte técnico. Entre em contato com o administrador da plataforma para maiores informações.')
                else:
                    # validate user password
                    is_pwd_valid = pbkdf2_sha256.verify(credentials['password'], user['password'])
                    if (is_pwd_valid is not True):
                        raise BusinessException('E-mail ou senha inválida.')

                    # deactivate all valid tokens
                    token_rep = TokenRepository(self.context)
                    # TODO: later on, reactivate..
                    # token_rep.deactivate_all(user)

                    # create a new token
                    token = {
                        'user': {
                            'id': user['id']
                        },
                        'is_active': True,
                        'code': str(uuid.uuid4())
                    }
                    token_rep.insert(token)

                    # get user permissions
                    permission_rep = PermissionRepository(self.context)
                    permissions = permission_rep.list(user)

                    # prepare modules permission wrapper
                    permissions_wrapper = {
                        'analyses': {
                            'view-all': False,
                            'create': False,
                            'delete': False,
                            'execute': False,
                            're-execute': False,
                            'send-to-analysis': False,
                            'set-final-decision': False,
                            'view-full-recommendation': False,
                            'issues': {
                                'create': False,
                                'delete': False,
                                'resolve': False
                            },
                            'priorities': {
                                'create': False,
                                'delete': False
                            }
                        },
                        'teams': {
                            'view': False
                        },
                        'portfolio': {
                            'view': False
                        },
                        'administration': {
                            'users': {
                                'view': False,
                                'create': False,
                                'update': False,
                                'delete': False
                            },
                            'banks': {
                                'setup': False
                            }
                        },
                        'superadmin': {
                            'view': False,
                            'simulations': False
                        }
                    }
                    if (permissions):
                        for permission in permissions:
                            if (permission['action'] == Permission.ANALYSIS_LIST_ALL):
                                permissions_wrapper['analyses']['view-all'] = True
                            elif (permission['action'] == Permission.ANALYSIS_INSERT):
                                permissions_wrapper['analyses']['create'] = True
                            elif (permission['action'] == Permission.ANALYSIS_DELETE):
                                permissions_wrapper['analyses']['delete'] = True
                            elif (permission['action'] == Permission.ANALYSIS_EXECUTE):
                                permissions_wrapper['analyses']['execute'] = True
                            elif (permission['action'] == Permission.ANALYSIS_REEXECUTE):
                                permissions_wrapper['analyses']['re-execute'] = True
                            elif (permission['action'] == Permission.ANALYSIS_SEND_TO_ANALYSIS):
                                permissions_wrapper['analyses']['send-to-analysis'] = True
                            elif (permission['action'] == Permission.ANALYSIS_FINAL_DECISION):
                                permissions_wrapper['analyses']['set-final-decision'] = True
                            elif (permission['action'] == Permission.ANALYSIS_CREATE_ISSUE):
                                permissions_wrapper['analyses']['issues']['create'] = True
                            elif (permission['action'] == Permission.ANALYSIS_VIEW_FULL_RECOMMENDATION):
                                permissions_wrapper['analyses']['view-full-recommendation'] = True
                            elif (permission['action'] == Permission.ANALYSIS_DELETE_ISSUE):
                                permissions_wrapper['analyses']['issues']['delete'] = True
                            elif (permission['action'] == Permission.ANALYSIS_RESOLVE_ISSUE):
                                permissions_wrapper['analyses']['issues']['resolve'] = True
                            elif (permission['action'] == Permission.ANALYSIS_CREATE_PRIORITY):
                                permissions_wrapper['analyses']['priorities']['create'] = True
                            elif (permission['action'] == Permission.ANALYSIS_DELETE_PRIORITY):
                                permissions_wrapper['analyses']['priorities']['delete'] = True
                            elif (permission['action'] == Permission.TEAMS_VIEW):
                                permissions_wrapper['teams']['view'] = True
                            elif (permission['action'] == Permission.PORTFOLIO_VIEW):
                                permissions_wrapper['portfolio']['view'] = True
                            elif (permission['action'] == Permission.SUPERADMIN_VIEW):
                                permissions_wrapper['superadmin']['view'] = True
                            elif (permission['action'] == Permission.USERS_VIEW):
                                permissions_wrapper['administration']['users']['view'] = True
                            elif (permission['action'] == Permission.USERS_INVITE):
                                permissions_wrapper['administration']['users']['create'] = True
                            elif (permission['action'] == Permission.USERS_UPDATE):
                                permissions_wrapper['administration']['users']['update'] = True
                            elif (permission['action'] == Permission.USERS_DELETE):
                                permissions_wrapper['administration']['users']['delete'] = True
                            elif (permission['action'] == Permission.BANKS_SETUP):
                                permissions_wrapper['administration']['banks']['setup'] = True

                    # finalize context
                    self.close_and_commit_context()

                    return {
                        'code': token['code'],
                        'user': {
                            'full_name': user['full_name'],
                            'email': user['email'],
                            'profile': user['profile'],
                            'company': {
                                'name': user['company']['name']
                            },
                            'permissions': permissions_wrapper
                        }
                    }
            else:
                raise BusinessException('E-mail ou senha inválida.')
        else:
            raise ManyExceptionsException(exceptions)

    # Logout an user
    def logout(self, token):
        # validate required fields
        exceptions = []
        if (not token['code']):
            exceptions.append(RequiredFieldException('É necessário informar o código do token.', 'token'))

        if (not exceptions):
            # prepare context
            self.initialize_context()
            self.context.connect_cockpit()

            userRep = UserRepository(self.context)

            user = userRep.get_by_token(token)
            if user:
                if user['status']['id'] == UserStatus.DELETED:
                    raise BusinessException(
                        'Este usuário está desativado. Entre em contato com o administrador da plataforma para maiores informações.')
                elif user['status']['id'] == UserStatus.SUSPENDED_BY_STAFF:
                    raise BusinessException(
                        'Este usuário foi suspenso pelo suporte técnico. Entre em contato com o administrador da plataforma para maiores informações.')
                else:
                    tokenRep = TokenRepository(self.context)

                    # deactivate all valid tokens
                    tokenRep.deactivate_all(user)

                    # finalize context
                    self.close_and_commit_context()

                    return {
                        'code': token['code']
                    }
            else:
                raise BusinessException('Token inválido.')
        else:
            raise ManyExceptionsException(exceptions)

    # Sends an email to the user with further instructions to reset password
    def request_reset_password(self, credentials):
        # validate required fields
        exceptions = []
        if (not credentials['email']):
            exceptions.append(RequiredFieldException('É necessário informar seu e-mail.', 'email'))
        elif (not validate_emaill(credentials['email'])):
            exceptions.append(RequiredFieldException('E-mail inválido.', 'email'))

        if (not exceptions):
            # prepare context
            self.initialize_context()
            self.context.connect_cockpit()

            userRep = UserRepository(self.context)

            user = userRep.get_by_email(credentials)
            if user:
                if user['status']['id'] == UserStatus.DELETED:
                    raise BusinessException(
                        'Este usuário está desativado. Entre em contato com o administrador da plataforma para maiores informações.')
                elif user['status']['id'] == UserStatus.SUSPENDED_BY_STAFF:
                    raise BusinessException(
                        'Este usuário foi suspenso pelo suporte técnico. Entre em contato com o administrador da plataforma para maiores informações.')
                else:
                    # deactivate all password reset requests
                    request = {
                        'email': credentials['email'],
                        'token': str(uuid.uuid4())[0: 30].upper(),
                        'is_active': True
                    }
                    requestRep = PasswordResetRequestRepository(self.context)
                    requestRep.deactivate_all(request)

                    # create a new password reset request
                    requestRep.insert(request)

                    # prepare url to reset password
                    # url = Server.URL + 'reset-password/' + str(request['token']) + '?msg=Um email foi enviado para ' + str(request['email']) + ' com mais instruções.&email=' + request['email']
                    url = Server.URL + 'reset-password/' + str(request['token']) + '/' + request['email']

                    # send e-mail
                    email = {
                        'to': request['email'],
                        'subject': 'Reinicialização de senha',
                        'body': 'Olá! <br><br> Você solicitou a reinicialização de sua senha na plataforma iRating. <br><br><a href="' + url + '">Clique aqui</a> para dar continuidade ao processo e informar uma nova senha. <br>Quando solicitado, informe o código: <b>' +
                                request['token'] + '</b><br><br>Atenciosamente,<br><b>Equipe iRating</b>'
                    }
                    emailBusiness = EmailBusiness(self.context)
                    emailBusiness.send(email)

                    # finalize context
                    self.close_and_commit_context()

                    return request
            else:
                raise BusinessException(
                    'E-mail não cadastrado em nossa base de dados. Contacte o administrador da plataforma para mais informações.')
        else:
            raise ManyExceptionsException(exceptions)

    # Reset user's own password
    def reset_own_password(self, request):
        # validate required fields
        exceptions = []
        if (not request['token']):
            exceptions.append(RequiredFieldException('É necessário informar o token.', 'token'))
        if (not request['email']):
            exceptions.append(RequiredFieldException('É necessário informar seu e-mail.', 'email'))
        if (not request['new_password']):
            exceptions.append(RequiredFieldException('É necessário informar sua nova senha.', 'new_password'))
        if (not request['new_password_confirmation']):
            exceptions.append(
                RequiredFieldException('É necessário confirmar sua nova senha.', 'new_password_confirmation'))
        elif (len(request['new_password']) < 8):
            exceptions.append(
                RequiredFieldException('Sua nova senha deve conter no mínimo 8 caracteres.', 'new_password'))
        elif (request['new_password'] != request['new_password_confirmation']):
            exceptions.append(
                RequiredFieldException('Confirmação da nova senha não confere.', 'new_password_confirmation'))

        if (not exceptions):
            # prepare context
            self.initialize_context()
            self.context.connect_cockpit()

            requestRep = PasswordResetRequestRepository(self.context)
            loaded_request = requestRep.get_valid_request(request)

            if loaded_request:
                userRep = UserRepository(self.context)

                user = userRep.get_by_email(request)
                if user:
                    if user['status']['id'] == UserStatus.DELETED:
                        raise BusinessException(
                            'Este usuário está desativado. Entre em contato com o administrador da plataforma para maiores informações.')
                    elif user['status']['id'] == UserStatus.SUSPENDED_BY_STAFF:
                        raise BusinessException(
                            'Este usuário foi suspenso pelo suporte técnico. Entre em contato com o administrador da plataforma para maiores informações.')
                    else:
                        # deactivate all password reset requests
                        requestRep = PasswordResetRequestRepository(self.context)
                        requestRep.deactivate_all(request)

                        flat_password = request['new_password']
                        # update user password
                        userToBeUpdated = {
                            'id': user['id'],
                            'password': UserBusiness.create_user_hash_password(self, flat_password)
                        }
                        userRep.update_password(userToBeUpdated)

                        # finalize context
                        self.close_and_commit_context()

                        return True
                else:
                    raise BusinessException(
                        'E-mail não cadastrado em nossa base de dados. Contacte o administrador da plataforma para mais informações.')
            else:
                raise BusinessException(
                    'Não foi possível reiniciar sua senha. Provavelmente, o código temporário enviado para seu e-mail está incorreto.')
        else:
            raise ManyExceptionsException(exceptions)

    # Reset an user password
    def reset_password(self, request, logged_user):
        if not logged_user:
            raise NotAuthenticatedException(
                'Você precisa estar logado para alterar seus dados. Efetue o login na plataforma.')

        # validate required fields
        exceptions = []
        if (not request.get('user', None)):
            exceptions.append(RequiredFieldException('É necessário informar o usuário.', 'user'))
        if (request.get('user', None) and not request['user']['id']):
            exceptions.append(RequiredFieldException('É necessário informar o ID do usuário.', 'user.id'))
        if (not request['new_password']):
            exceptions.append(RequiredFieldException('É necessário informar sua nova senha.', 'new_password'))
        if (not request['new_password_confirmation']):
            exceptions.append(
                RequiredFieldException('É necessário confirmar sua nova senha.', 'new_password_confirmation'))
        elif (len(request['new_password']) < 8):
            exceptions.append(
                RequiredFieldException('Sua nova senha deve conter no mínimo 8 caracteres.', 'new_password'))
        elif (request['new_password'] != request['new_password_confirmation']):
            exceptions.append(
                RequiredFieldException('Confirmação da nova senha não confere.', 'new_password_confirmation'))

        if (not exceptions):
            # prepare context
            self.initialize_context()
            self.context.connect_cockpit()

            # check permission if user has permission to update other users
            permRep = PermissionRepository(self.context)
            permission = permRep.get({'user': {'id': logged_user['id']}, 'action': Permission.USERS_UPDATE})
            if not permission:
                raise NotAuthorizedException('Você não possui permissão para alterar os dados de outros usuários.')

            # get user
            userRep = UserRepository(self.context)
            user = userRep.get(request['user'])
            if user:
                if user['status']['id'] == UserStatus.DELETED:
                    raise BusinessException(
                        'Este usuário está desativado. Entre em contato com o administrador da plataforma para maiores informações.')
                elif user['status']['id'] == UserStatus.SUSPENDED_BY_STAFF:
                    raise BusinessException(
                        'Este usuário foi suspenso pelo suporte técnico. Entre em contato com o administrador da plataforma para maiores informações.')
                else:
                    # update user password
                    userToBeUpdated = {
                        'id': user['id'],
                        'password': UserBusiness.create_user_hash_password(self, request['new_password'])
                    }
                    userRep.update_password(userToBeUpdated)

                    # finalize context
                    self.close_and_commit_context()

                    return True
            else:
                raise BusinessException(
                    'Usuário não cadastrado em nossa base de dados. Contacte o administrador da plataforma para mais informações.')
        else:
            raise ManyExceptionsException(exceptions)

    def self_update(self, user, loggedUser):
        if not loggedUser:
            raise NotAuthenticatedException(
                'Você precisa estar logado para alterar seus dados. Efetue o login na plataforma.')

        # user can only update himself
        user['id'] = loggedUser['id']

        # validate required fields
        exceptions = []
        if (not user['email']):
            exceptions.append(RequiredFieldException('É necessário informar o e-mail.', 'email'))
        elif (not validate_emaill(user['email'])):
            exceptions.append(RequiredFieldException('E-mail inválido.', 'email'))
        if (not user['full_name']):
            exceptions.append(RequiredFieldException('É necessário informar o nome completo.', 'full_name'))
        if (user['new_password']):
            if (not user['new_password_confirmation']):
                exceptions.append(
                    RequiredFieldException('É necessário confirmar a nova senha.', 'new_password_confirmation'))
            elif (len(user['new_password']) < 8):
                exceptions.append(
                    RequiredFieldException('A nova senha deve conter no mínimo 8 caracteres.', 'new_password'))
            elif (user['new_password'] != user['new_password_confirmation']):
                exceptions.append(
                    RequiredFieldException('Confirmação da nova senha não confere.', 'new_password_confirmation'))

        if (not exceptions):
            # initialize context
            self.initialize_context()
            self.context.connect_cockpit()

            # check if user exists
            userRep = UserRepository(self.context)
            loadedUser = userRep.get(user)

            # check if current password is correct
            if user['new_password']:
                # update user password
                user['new_password'] = self.create_user_hash_password(user['new_password'])
                userRep.update_password({'id': user['id'], 'password': user['new_password']})

            # keep current status and profile
            user['status'] = loadedUser['status']
            user['profile'] = loadedUser['profile']
            if (loadedUser['supervisor']):
                user['supervisor'] = loadedUser['supervisor']
            else:
                user['supervisor'] = {
                    'id': None
                }

            # update user
            userRep.update(user)

            # finalize context
            self.close_and_commit_context()

            return {
                'full_name': user['full_name'],
                'email': user['email']
            }
        else:
            raise ManyExceptionsException(exceptions)

    def set_user_permissions(self, user):
        # create permission list according to user profile
        permissions = []
        if user['profile']['id'] == UserProfile.SUPERADMIN:
            permissions.append({'user': user, 'action': Permission.ANALYSIS_INSERT})
            permissions.append({'user': user, 'action': Permission.ANALYSIS_UPDATE})
            permissions.append({'user': user, 'action': Permission.ANALYSIS_EXECUTE})
            permissions.append({'user': user, 'action': Permission.ANALYSIS_SEND_TO_ANALYSIS})
            permissions.append({'user': user, 'action': Permission.ANALYSIS_VIEW_FULL_RECOMMENDATION})
            permissions.append({'user': user, 'action': Permission.ANALYSIS_FINAL_DECISION})
            permissions.append({'user': user, 'action': Permission.ANALYSIS_REEXECUTE})
            permissions.append({'user': user, 'action': Permission.ANALYSIS_LIST_ALL})
            permissions.append({'user': user, 'action': Permission.ANALYSIS_CREATE_ISSUE})
            permissions.append({'user': user, 'action': Permission.ANALYSIS_DELETE_ISSUE})
            permissions.append({'user': user, 'action': Permission.ANALYSIS_RESOLVE_ISSUE})
            permissions.append({'user': user, 'action': Permission.ANALYSIS_CREATE_PRIORITY})
            permissions.append({'user': user, 'action': Permission.ANALYSIS_DELETE_PRIORITY})
            permissions.append({'user': user, 'action': Permission.TEAMS_VIEW})
            permissions.append({'user': user, 'action': Permission.PORTFOLIO_VIEW})
            permissions.append({'user': user, 'action': Permission.SUPERADMIN_VIEW})
            permissions.append({'user': user, 'action': Permission.USERS_VIEW})
            permissions.append({'user': user, 'action': Permission.USERS_INVITE})
            permissions.append({'user': user, 'action': Permission.USERS_UPDATE})
            permissions.append({'user': user, 'action': Permission.BANKS_SETUP})
        elif user['profile']['id'] == UserProfile.ADMINISTRATOR:
            permissions.append({'user': user, 'action': Permission.ANALYSIS_INSERT})
            permissions.append({'user': user, 'action': Permission.ANALYSIS_UPDATE})
            permissions.append({'user': user, 'action': Permission.ANALYSIS_EXECUTE})
            permissions.append({'user': user, 'action': Permission.ANALYSIS_SEND_TO_ANALYSIS})
            permissions.append({'user': user, 'action': Permission.ANALYSIS_VIEW_FULL_RECOMMENDATION})
            permissions.append({'user': user, 'action': Permission.ANALYSIS_FINAL_DECISION})
            permissions.append({'user': user, 'action': Permission.ANALYSIS_REEXECUTE})
            permissions.append({'user': user, 'action': Permission.ANALYSIS_LIST_ALL})
            permissions.append({'user': user, 'action': Permission.ANALYSIS_CREATE_ISSUE})
            permissions.append({'user': user, 'action': Permission.ANALYSIS_DELETE_ISSUE})
            permissions.append({'user': user, 'action': Permission.ANALYSIS_RESOLVE_ISSUE})
            permissions.append({'user': user, 'action': Permission.ANALYSIS_CREATE_PRIORITY})
            permissions.append({'user': user, 'action': Permission.ANALYSIS_DELETE_PRIORITY})
            permissions.append({'user': user, 'action': Permission.TEAMS_VIEW})
            permissions.append({'user': user, 'action': Permission.PORTFOLIO_VIEW})
            permissions.append({'user': user, 'action': Permission.USERS_VIEW})
            permissions.append({'user': user, 'action': Permission.USERS_INVITE})
            permissions.append({'user': user, 'action': Permission.USERS_UPDATE})
            permissions.append({'user': user, 'action': Permission.BANKS_SETUP})
        elif user['profile']['id'] == UserProfile.ANALYST:
            permissions.append({'user': user, 'action': Permission.ANALYSIS_INSERT})
            permissions.append({'user': user, 'action': Permission.ANALYSIS_UPDATE})
            permissions.append({'user': user, 'action': Permission.ANALYSIS_EXECUTE})
            permissions.append({'user': user, 'action': Permission.ANALYSIS_SEND_TO_ANALYSIS})
            permissions.append({'user': user, 'action': Permission.ANALYSIS_VIEW_FULL_RECOMMENDATION})
            permissions.append({'user': user, 'action': Permission.ANALYSIS_FINAL_DECISION})
            permissions.append({'user': user, 'action': Permission.ANALYSIS_LIST_ALL})
            permissions.append({'user': user, 'action': Permission.ANALYSIS_CREATE_ISSUE})
            permissions.append({'user': user, 'action': Permission.ANALYSIS_DELETE_ISSUE})
            permissions.append({'user': user, 'action': Permission.ANALYSIS_RESOLVE_ISSUE})
        elif user['profile']['id'] == UserProfile.OPERATOR:
            permissions.append({'user': user, 'action': Permission.ANALYSIS_INSERT})
            permissions.append({'user': user, 'action': Permission.ANALYSIS_UPDATE})
            permissions.append({'user': user, 'action': Permission.ANALYSIS_SEND_TO_ANALYSIS})
            permissions.append({'user': user, 'action': Permission.ANALYSIS_RESOLVE_ISSUE})
            permissions.append({'user': user, 'action': Permission.ANALYSIS_VIEW_FULL_RECOMMENDATION})
        elif user['profile']['id'] == UserProfile.EXTERNAL_OPERATOR:
            permissions.append({'user': user, 'action': Permission.ANALYSIS_INSERT})
            permissions.append({'user': user, 'action': Permission.ANALYSIS_UPDATE})
            permissions.append({'user': user, 'action': Permission.ANALYSIS_SEND_TO_ANALYSIS})
            permissions.append({'user': user, 'action': Permission.ANALYSIS_RESOLVE_ISSUE})
        elif user['profile']['id'] == UserProfile.SUPERVISOR or user['profile']['id'] == UserProfile.MANAGER:
            permissions.append({'user': user, 'action': Permission.ANALYSIS_INSERT})
            permissions.append({'user': user, 'action': Permission.ANALYSIS_UPDATE})
            permissions.append({'user': user, 'action': Permission.ANALYSIS_EXECUTE})
            permissions.append({'user': user, 'action': Permission.ANALYSIS_SEND_TO_ANALYSIS})
            permissions.append({'user': user, 'action': Permission.ANALYSIS_VIEW_FULL_RECOMMENDATION})
            permissions.append({'user': user, 'action': Permission.ANALYSIS_FINAL_DECISION})
            permissions.append({'user': user, 'action': Permission.ANALYSIS_REEXECUTE})
            permissions.append({'user': user, 'action': Permission.ANALYSIS_LIST_ALL})
            permissions.append({'user': user, 'action': Permission.ANALYSIS_CREATE_ISSUE})
            permissions.append({'user': user, 'action': Permission.ANALYSIS_DELETE_ISSUE})
            permissions.append({'user': user, 'action': Permission.ANALYSIS_RESOLVE_ISSUE})
            permissions.append({'user': user, 'action': Permission.ANALYSIS_CREATE_PRIORITY})
            permissions.append({'user': user, 'action': Permission.ANALYSIS_DELETE_PRIORITY})
            permissions.append({'user': user, 'action': Permission.TEAMS_VIEW})
            permissions.append({'user': user, 'action': Permission.USERS_VIEW})
            permissions.append({'user': user, 'action': Permission.USERS_INVITE})
            permissions.append({'user': user, 'action': Permission.USERS_UPDATE})

        # insert permissions to the user
        permission_rep = PermissionRepository(self.context)
        for permission in permissions:
            permission_rep.insert(permission)

    def signup(self, user):
        # validate required fields
        exceptions = []
        if (not user['email']):
            exceptions.append(RequiredFieldException('É necessário informar seu e-mail.', 'email'))
        elif (not validate_emaill(user['email'])):
            exceptions.append(RequiredFieldException('E-mail inválido.', 'email'))
        if (not user['access_code']):
            exceptions.append(
                RequiredFieldException('É necessário informar seu código de acesso temporário.', 'access_code'))
        if (not user['password']):
            exceptions.append(RequiredFieldException('É necessário informar sua senha.', 'password'))
        if (not user['password_confirmation']):
            exceptions.append(RequiredFieldException('É necessário confirmar sua senha.', 'password_confirmation'))
        elif (len(user['password']) < 8):
            exceptions.append(RequiredFieldException('Sua senha deve conter no mínimo 8 caracteres.', 'password'))
        elif (user['password'] != user['password_confirmation']):
            exceptions.append(RequiredFieldException('Confirmação da senha não confere.', 'password_confirmation'))

        if (not exceptions):
            # prepare context
            self.initialize_context()
            self.context.connect_cockpit()

            userRep = UserRepository(self.context)

            # check if user exists
            loadedUser = userRep.get_by_email(user)
            if loadedUser:
                if loadedUser['status']['id'] == UserStatus.DELETED:
                    raise BusinessException(
                        'Este usuário está desativado. Entre em contato com o administrador da plataforma para maiores informações.')
                elif loadedUser['status']['id'] == UserStatus.ACTIVE:
                    raise BusinessException(
                        'Este procedimento já foi realizado. Por favor, entre em contato com o administrador da plataforma para mais informações.')
                elif loadedUser['status']['id'] == UserStatus.SUSPENDED_BY_STAFF:
                    raise BusinessException(
                        'Este usuário foi suspenso pelo suporte técnico. Entre em contato com o administrador da plataforma para maiores informações.')
                else:
                    # get user invite
                    invite = {
                        'user': {
                            'id': loadedUser['id']
                        },
                        'access_code': user['access_code']
                    }
                    inviteRep = UserInviteRepository(self.context)
                    loadedUserInvite = inviteRep.get_valid_invite(invite)

                    if loadedUserInvite:
                        # update user password
                        flat_password = user['password']
                        hash_password = self.create_user_hash_password(flat_password)

                        userToBeUpdated = {
                            'id': loadedUser['id'],
                            'password': hash_password,
                            'status': {
                                'id': UserStatus.ACTIVE
                            }
                        }
                        userRep.update_password(userToBeUpdated)

                        # update user status
                        userRep.update_status(userToBeUpdated)

                        # redeem invite
                        inviteRep.redeem(loadedUserInvite)

                        # finalize context
                        self.close_and_commit_context()

                        return self.login({
                            'email': user['email'],
                            'password': user['password']
                        })
                    else:
                        raise BusinessException(
                            'E-mail ou código de acesso temporário incorreto. Verifique se foi digitado corretamente e se o convite não expirou (validade informada no e-mail de convite).')
            else:
                raise BusinessException(
                    'Usuário inexistente. Por favor, entre em contato com o administrador da plataforma para mais informações.')
        else:
            raise ManyExceptionsException(exceptions)

    def update(self, user, loggedUser):
        if not loggedUser:
            raise NotAuthenticatedException(
                'Você precisa estar logado para alterar os dados de um usuário. Efetue o login na plataforma.')

        # initialize context
        self.initialize_context()
        self.context.connect_cockpit()

        # check permission if user has permission to update other users
        permRep = PermissionRepository(self.context)
        permission = permRep.get({'user': {'id': loggedUser['id']}, 'action': Permission.USERS_UPDATE})
        if not permission:
            raise NotAuthorizedException('Você não possui permissão para alterar os dados de outros usuários.')

        # validate required fields
        exceptions = []
        if (not user['email']):
            exceptions.append(RequiredFieldException('É necessário informar o e-mail.', 'email'))
        elif (not validate_emaill(user['email'])):
            exceptions.append(RequiredFieldException('E-mail inválido.', 'email'))
        if (not user['full_name']):
            exceptions.append(RequiredFieldException('É necessário informar o nome completo.', 'full_name'))
        if (not user['status']['id']):
            exceptions.append(RequiredFieldException('É necessário informar o status do usuário.', 'status.id'))
        if (not user['profile']['id']):
            exceptions.append(RequiredFieldException('É necessário informar o perfil do usuário.', 'profile.id'))
        if (user['new_password']):
            if (not user['new_password_confirmation']):
                exceptions.append(
                    RequiredFieldException('É necessário confirmar a nova senha.', 'new_password_confirmation'))
            elif (len(user['new_password']) < 8):
                exceptions.append(
                    RequiredFieldException('A nova senha deve conter no mínimo 8 caracteres.', 'new_password'))
            elif (user['new_password'] != user['new_password_confirmation']):
                exceptions.append(
                    RequiredFieldException('Confirmação da nova senha não confere.', 'new_password_confirmation'))

        if (not exceptions):
            # check if user exists
            userRep = UserRepository(self.context)
            loadedUser = userRep.get(user)

            if loadedUser:
                # update password
                if user['new_password']:
                    flat_password = user['new_password']
                    hash_password = self.create_user_hash_password(flat_password)
                    userRep.update_password({'id': user['id'], 'password': hash_password})

                # update user
                userRep.update(user)

                # update user permmissions
                permissions = []
                if user['profile']['id'] == UserProfile.SUPERADMIN:
                    permissions.append({'user': user, 'action': Permission.ANALYSIS_INSERT})
                    permissions.append({'user': user, 'action': Permission.ANALYSIS_UPDATE})
                    permissions.append({'user': user, 'action': Permission.ANALYSIS_EXECUTE})
                    permissions.append({'user': user, 'action': Permission.ANALYSIS_SEND_TO_ANALYSIS})
                    permissions.append({'user': user, 'action': Permission.ANALYSIS_VIEW_FULL_RECOMMENDATION})
                    permissions.append({'user': user, 'action': Permission.ANALYSIS_FINAL_DECISION})
                    permissions.append({'user': user, 'action': Permission.ANALYSIS_REEXECUTE})
                    permissions.append({'user': user, 'action': Permission.ANALYSIS_LIST_ALL})
                    permissions.append({'user': user, 'action': Permission.ANALYSIS_CREATE_ISSUE})
                    permissions.append({'user': user, 'action': Permission.ANALYSIS_DELETE_ISSUE})
                    permissions.append({'user': user, 'action': Permission.ANALYSIS_RESOLVE_ISSUE})
                    permissions.append({'user': user, 'action': Permission.ANALYSIS_CREATE_PRIORITY})
                    permissions.append({'user': user, 'action': Permission.ANALYSIS_DELETE_PRIORITY})
                    permissions.append({'user': user, 'action': Permission.TEAMS_VIEW})
                    permissions.append({'user': user, 'action': Permission.PORTFOLIO_VIEW})
                    permissions.append({'user': user, 'action': Permission.SUPERADMIN_VIEW})
                    permissions.append({'user': user, 'action': Permission.USERS_VIEW})
                    permissions.append({'user': user, 'action': Permission.USERS_INVITE})
                    permissions.append({'user': user, 'action': Permission.USERS_UPDATE})
                    permissions.append({'user': user, 'action': Permission.BANKS_SETUP})
                elif user['profile']['id'] == UserProfile.ADMINISTRATOR:
                    permissions.append({'user': user, 'action': Permission.ANALYSIS_INSERT})
                    permissions.append({'user': user, 'action': Permission.ANALYSIS_UPDATE})
                    permissions.append({'user': user, 'action': Permission.ANALYSIS_EXECUTE})
                    permissions.append({'user': user, 'action': Permission.ANALYSIS_SEND_TO_ANALYSIS})
                    permissions.append({'user': user, 'action': Permission.ANALYSIS_VIEW_FULL_RECOMMENDATION})
                    permissions.append({'user': user, 'action': Permission.ANALYSIS_FINAL_DECISION})
                    permissions.append({'user': user, 'action': Permission.ANALYSIS_REEXECUTE})
                    permissions.append({'user': user, 'action': Permission.ANALYSIS_LIST_ALL})
                    permissions.append({'user': user, 'action': Permission.ANALYSIS_CREATE_ISSUE})
                    permissions.append({'user': user, 'action': Permission.ANALYSIS_DELETE_ISSUE})
                    permissions.append({'user': user, 'action': Permission.ANALYSIS_RESOLVE_ISSUE})
                    permissions.append({'user': user, 'action': Permission.ANALYSIS_CREATE_PRIORITY})
                    permissions.append({'user': user, 'action': Permission.ANALYSIS_DELETE_PRIORITY})
                    permissions.append({'user': user, 'action': Permission.TEAMS_VIEW})
                    permissions.append({'user': user, 'action': Permission.PORTFOLIO_VIEW})
                    permissions.append({'user': user, 'action': Permission.USERS_VIEW})
                    permissions.append({'user': user, 'action': Permission.USERS_INVITE})
                    permissions.append({'user': user, 'action': Permission.USERS_UPDATE})
                    permissions.append({'user': user, 'action': Permission.BANKS_SETUP})
                elif user['profile']['id'] == UserProfile.ANALYST:
                    permissions.append({'user': user, 'action': Permission.ANALYSIS_INSERT})
                    permissions.append({'user': user, 'action': Permission.ANALYSIS_UPDATE})
                    permissions.append({'user': user, 'action': Permission.ANALYSIS_EXECUTE})
                    permissions.append({'user': user, 'action': Permission.ANALYSIS_SEND_TO_ANALYSIS})
                    permissions.append({'user': user, 'action': Permission.ANALYSIS_VIEW_FULL_RECOMMENDATION})
                    permissions.append({'user': user, 'action': Permission.ANALYSIS_FINAL_DECISION})
                    permissions.append({'user': user, 'action': Permission.ANALYSIS_LIST_ALL})
                    permissions.append({'user': user, 'action': Permission.ANALYSIS_CREATE_ISSUE})
                    permissions.append({'user': user, 'action': Permission.ANALYSIS_DELETE_ISSUE})
                    permissions.append({'user': user, 'action': Permission.ANALYSIS_RESOLVE_ISSUE})
                elif user['profile']['id'] == UserProfile.OPERATOR:
                    permissions.append({'user': user, 'action': Permission.ANALYSIS_INSERT})
                    permissions.append({'user': user, 'action': Permission.ANALYSIS_UPDATE})
                    permissions.append({'user': user, 'action': Permission.ANALYSIS_SEND_TO_ANALYSIS})
                    permissions.append({'user': user, 'action': Permission.ANALYSIS_RESOLVE_ISSUE})
                    permissions.append({'user': user, 'action': Permission.ANALYSIS_VIEW_FULL_RECOMMENDATION})
                elif user['profile']['id'] == UserProfile.EXTERNAL_OPERATOR:
                    permissions.append({'user': user, 'action': Permission.ANALYSIS_INSERT})
                    permissions.append({'user': user, 'action': Permission.ANALYSIS_UPDATE})
                    permissions.append({'user': user, 'action': Permission.ANALYSIS_SEND_TO_ANALYSIS})
                    permissions.append({'user': user, 'action': Permission.ANALYSIS_RESOLVE_ISSUE})
                elif user['profile']['id'] == UserProfile.SUPERVISOR or user['profile']['id'] == UserProfile.MANAGER:
                    permissions.append({'user': user, 'action': Permission.ANALYSIS_INSERT})
                    permissions.append({'user': user, 'action': Permission.ANALYSIS_UPDATE})
                    permissions.append({'user': user, 'action': Permission.ANALYSIS_EXECUTE})
                    permissions.append({'user': user, 'action': Permission.ANALYSIS_SEND_TO_ANALYSIS})
                    permissions.append({'user': user, 'action': Permission.ANALYSIS_VIEW_FULL_RECOMMENDATION})
                    permissions.append({'user': user, 'action': Permission.ANALYSIS_FINAL_DECISION})
                    permissions.append({'user': user, 'action': Permission.ANALYSIS_REEXECUTE})
                    permissions.append({'user': user, 'action': Permission.ANALYSIS_LIST_ALL})
                    permissions.append({'user': user, 'action': Permission.ANALYSIS_CREATE_ISSUE})
                    permissions.append({'user': user, 'action': Permission.ANALYSIS_DELETE_ISSUE})
                    permissions.append({'user': user, 'action': Permission.ANALYSIS_RESOLVE_ISSUE})
                    permissions.append({'user': user, 'action': Permission.ANALYSIS_CREATE_PRIORITY})
                    permissions.append({'user': user, 'action': Permission.ANALYSIS_DELETE_PRIORITY})
                    permissions.append({'user': user, 'action': Permission.TEAMS_VIEW})
                    permissions.append({'user': user, 'action': Permission.USERS_VIEW})
                    permissions.append({'user': user, 'action': Permission.USERS_INVITE})
                    permissions.append({'user': user, 'action': Permission.USERS_UPDATE})

                # delete current permissions
                permission_rep = PermissionRepository(self.context)
                permission_rep.delete_all(user)

                # insert permissions to the user
                for permission in permissions:
                    permission_rep.insert(permission)

                # finalize context
                self.close_and_commit_context()
            else:
                raise BusinessException('Usuário inexistente.')
        else:
            raise ManyExceptionsException(exceptions)

    def crypto_all_users_passwords(self, loggedUser):
        if not loggedUser:
            raise NotAuthenticatedException(
                'Você precisa estar logado para alterar os dados de um usuário. Efetue o login na plataforma.')

        # initialize context
        self.initialize_context()
        self.context.connect_cockpit()

        # check permission if user has permission to update other users
        permRep = PermissionRepository(self.context)
        permission = permRep.get({'user': {'id': loggedUser['id']}, 'action': Permission.USERS_UPDATE})
        if not permission:
            raise NotAuthorizedException('Você não possui permissão para alterar os dados de outros usuários.')

        userRep = UserRepository(self.context)
        all_users = userRep.list_all()

        if all_users:
            for user in all_users:
                flat_password = user['password']

                if (flat_password and flat_password.find("$pbkdf2-sha256") == -1):
                    hash_password = self.create_user_hash_password(flat_password)
                    new_user_pwd = {
                        'id': user['id'],
                        'password': hash_password
                    }
                    userRep.update_password(new_user_pwd)

            # finalize context
            self.close_and_commit_context()

        return True

    # validate an user token
    def validate_token(self, token):
        # validate required fields
        exceptions = []
        if (not token.get('code', None)):
            exceptions.append(RequiredFieldException('É necessário informar o código do token.', 'token'))
        if (not token.get('user', None)):
            exceptions.append(RequiredFieldException('É necessário informar os dados do usuário.', 'user'))
        else:
            if (not token['user'].get('email', None)):
                exceptions.append(RequiredFieldException('É necessário informar o e-mail do usuário.', 'user.email'))

        if (not exceptions):
            # prepare context
            self.initialize_context()
            self.context.connect_cockpit()

            tokenRep = TokenRepository(self.context)

            token = tokenRep.get_by_code_email(token)

            # finalize context
            self.close_and_commit_context()

            if token and token['is_active']:
                return True
            else:
                return False
        else:
            raise ManyExceptionsException(exceptions)
