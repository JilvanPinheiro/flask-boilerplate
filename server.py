import flask
import os
import sys


# import services classes
from service.hello_wold_service import HelloWorldService


# set default encoding
reload(sys)
sys.setdefaultencoding('utf-8')

# create flask app
app = flask.app()

# set security options
@app.hook('after_request')
def enable_cors():
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'PUT, GET, POST, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Origin, Accept, Content-Type, X-Requested-With, X-CSRF-Token, token'


# example of endpoint
@app.route('/helloworld', method=['OPTIONS', 'GET'])
def hello_world():
    if request.method != "OTIONS":
        service = HelloWorldService()
        return (service.print_message)
