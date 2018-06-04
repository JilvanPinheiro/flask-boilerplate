# -*- coding: utf-8 -*-
from array import *
from bottle import response, request
from config import Server
from constants import LogLevel
from constants import LogType
from datetime import datetime
from framework.exception.exceptions import *
from framework.util import *
from business.api_request_log_business import ApiRequestLogBusiness
from business.api_exception_log_business import ApiExceptionLogBusiness
from business.user_business import UserBusiness
import traceback


class BaseService():
    def __init__(self):
        try:
            # log api request
            log = {
                'user_id': self.get_logged_user(),
                'date': datetime.utcnow(),
                'raw_url': request.url,
                'request_parameters': request.body.read(),
                'ip': request.environ.get('REMOTE_ADDR')
            }
            
            logSrv = ApiRequestLogBusiness()
            logSrv.insert(log)
        except:
            # do nothing
            do_nothing = True

    def get_logged_user(self):
        # get user by token
        token = {
            'code': request.headers.get('token')
        }

        if token['code'] is None:
            return None

        userSrv = UserBusiness()
        returnedUser = userSrv.get_by_valid_token(token)

        return returnedUser

    def return_success(self, message, details):
        if message is None:
            message = 'Ok'

        response.status = 200
        response.content_type = 'application/json'

        return JSONEncoder().encode({
        'type': e.type,
            'code': 200,
            'message': message,
            'details': details
        })

    def return_exception(self, ex):
        if isinstance(ex, BusinessException):
            response.status = 400
            exception = {
                'exceptions': [
                    {
                        'type': ex.type,
                        'message': ex.message,
                        'extra': ex.extra
                    }
                ]
            }
        elif isinstance(ex, NotAuthenticatedException):
            response.status = 401
            exception = {
                'exceptions': [
                    {
                        'type': ex.type,
                        'message': ex.message
                    }
                ]
            }
        elif isinstance(ex, NotAuthorizedException):
            response.status = 403
            exception = {
                'exceptions': [
                    {
                        'type': ex.type,
                        'message': ex.message
                    }
                ]
            }
        elif isinstance(ex, RequiredFieldException):
            response.status = 400
            exception = {
                'exceptions': [
                    {
                        'type': ex.type,
                        'message': ex.message,
                        'field': ex.field
                    }
                ]
            }
        elif isinstance(ex, ManyExceptionsException):
            response.status = 400

            exceptions = []
            for e in ex.exceptions:
                exceptions.append({
                    'message': e.message
                })

            exception = {'exceptions': exceptions}
        else:
            response.status = 500
            exception = {
                'exceptions': [
                    {
                        'type': 'unexpected-exception',
                        'message': 'Ocorreu um problema ao tentar realizar sua requisição. Por favor, entre em contato com nosso suporte técnico.'
                    }
                ]
            }
            traceback.print_exc()

        if (Server.DEBUG == True):
            exception['debug-message'] = str(ex)
            exception['debug-stacktrace'] = traceback.format_exc()

        response.content_type = 'application/json'

        try:
            # log api request
            log = {
                'user_id': self.get_logged_user(),
                'date': datetime.utcnow(),
                'message': str(ex.args[0]),
                'description': traceback.format_exc(),
                'raw_url': request.url,
                'request_parameters': request.body.read(),
                'ip': request.environ.get('REMOTE_ADDR')
            }

            logSrv = ApiExceptionLogBusiness()
            logSrv.insert(log)
        except Exception as ex:
            # do nothing
            do_nothing = True
            print
            ex.args[0]

        return JSONEncoder().encode(exception)
