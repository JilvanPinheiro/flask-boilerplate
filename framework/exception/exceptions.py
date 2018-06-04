class BusinessException(Exception):
    type = 'business-exception'
    message = None
    extra = None

    def __init__(self, *args):
        self.args = args
        self.message = args[0]
        if len(args) >= 2:
            self.extra = args[1]


class NotAuthenticatedException(Exception):
    type = 'not-authenticated-exception'
    message = None

    def __init__(self, *args):
        self.args = args
        self.message = args[0]


class NotAuthorizedException(Exception):
    type = 'not-authorized-exception'
    message = None

    def __init__(self, *args):
        self.args = args
        self.message = args[0]


class RequiredFieldException(Exception):
    type = 'required-field-exception'
    message = None
    field = None

    def __init__(self, *args):
        self.args = args
        self.message = args[0]
        self.field = args[1]


class ManyExceptionsException(Exception):
    type = 'many-exceptions-exception'
    exceptions = None

    def __init__(self, *args):
        self.args = args
        self.exceptions = args[0]
