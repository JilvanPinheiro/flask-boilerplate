import os

# server configuration
class Server():
    ENVIRONMENT = os.environ["SERVER_ENVIRONMENT"]
    DEBUG = (os.environ["SERVER_DEBUG"] == "True")
    PORT = os.environ["SERVER_PORT"]
    API_VERSION = os.environ["SERVER_API_VERSION"]
    URL = os.environ["SERVER_URL"]

# email configuration
class EmailConfiguration():
    FROM = os.environ["EMAIL_CONFIGURATION_FROM"]
    SMTP = os.environ["EMAIL_CONFIGURATION_SMTP"]
    PORT = os.environ["EMAIL_CONFIGURATION_SMTP_PORT"]
    USERNAME = os.environ["EMAIL_CONFIGURATION_USERNAME"]
    PASSWORD = os.environ["EMAIL_CONFIGURATION_PASSWORD"]
    DEVELOPMENT_EMAIL = os.environ["EMAIL_CONFIGURATION_DEVELOPMENT_EMAIL"]


# MySQL database connection
class MysqlDb():
    HOST = os.environ["MYSQL_DB_HOST"]
    PORT = os.environ["MYSQL_DB_PORT"]
    DATABASE = os.environ["MYSQL_DB_DATABASE"]
    USER_ID = os.environ["MYSQL_DB_USER_ID"]
    PASSWORD = os.environ["MYSQL_DB_PASSWORD"]

# cockpit nosql database connection
class NoSqlDb():
    HOST = os.environ["NO_SQL_DB_HOST"]
    PORT = os.environ["NO_SQL_DB_PORT"]
    DATABASE = os.environ["NO_SQL_DB_DATABASE"]
    USER_ID = os.environ["NO_SQL_DB_USER_ID"]
    PASSWORD = os.environ["NO_SQL_DB_PASSWORD"]
