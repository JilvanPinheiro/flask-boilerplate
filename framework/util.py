# -*- coding: utf-8 -*-
import json
from bson import ObjectId
from validate_email import validate_email
import datetime


def validate_emaill(email):
    return email and validate_email(email)


def validate_date(date_text):
    try:
        datetime.datetime.strptime(date_text, '%Y-%m-%d')
        return True
    except ValueError:
        return False


def validate_cpf(cpf):
    """
    Tests:
    >>> print Cpf().validate('91289037736')
    True
    >>> print Cpf().validate('91289037731')
    False
    """
    cpf_invalidos = [11 * str(i) for i in range(10)]
    if cpf in cpf_invalidos:
        return False

    if not cpf.isdigit():
        """ Verifica se o CPF contem pontos e hifens """
        cpf = cpf.replace(".", "")
        cpf = cpf.replace("-", "")

    if len(cpf) < 11:
        """ Verifica se o CPF tem 11 digitos """
        return False

    if len(cpf) > 11:
        """ CPF tem que ter 11 digitos """
        return False

    selfcpf = [int(x) for x in cpf]

    cpf = selfcpf[:9]

    while len(cpf) < 11:

        r = sum([(len(cpf) + 1 - i) * v for i, v in [(x, cpf[x]) for x in range(len(cpf))]]) % 11

        if r > 1:
            f = 11 - r
        else:
            f = 0
        cpf.append(f)

    return bool(cpf == selfcpf)


class JSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, ObjectId):
            return str(o)
        elif isinstance(o, datetime.datetime):
            return str(o)
        elif isinstance(o, datetime.date):
            return str(o)
        return json.JSONEncoder.default(self, o)


def safe_get(document, path):
    if document == None or path == None or path == '':
        return None
    else:
        last_level = document
        keys = path.split('.')

        if len(keys) == 0:
            return None

        for i in range(0, len(keys)):
            if not isinstance(last_level, list):
                last_level = last_level.get(keys[i], None)
            else:
                if len(last_level) == 0:
                    return None
                else:
                    last_level = last_level[0].get(keys[i], None)

            if last_level == None:
                return None

            if i == (len(keys) - 1):
                return last_level
