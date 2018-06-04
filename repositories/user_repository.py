# -*- coding: utf-8 -*-
from base_repository import CockpitRepository
import pyodbc


class UserRepository(CockpitRepository):
    def get(self, user):
        row = self.execute(
            'SELECT u.user_id, u.user_status_id, u.profile_id, u.email, u.full_name, us.description, u.supervisor_id, s.full_name AS \'supervisor_full_name\', u.password FROM user u INNER JOIN user_status us ON us.user_status_id = u.user_status_id LEFT JOIN user s ON s.user_id = u.supervisor_id WHERE u.user_id = %s',
            user['id']).fetchone()

        returnUser = None
        if row:
            returnUser = {
                'id': row['user_id'],
                'email': row['email'],
                'full_name': row['full_name'],
                'password': row['password'],
                'status': {
                    'id': row['user_status_id'],
                    'description': row['description']
                },
                'profile': {
                    'id': row['profile_id']
                }
            }
            if row['supervisor_id']:
                returnUser['supervisor'] = {
                    'id': row['supervisor_id'],
                    'full_name': row['supervisor_full_name']
                }
            else:
                returnUser['supervisor'] = None

        return returnUser

    def get_by_email(self, user):
        row = self.execute(
            'SELECT u.user_id, u.user_status_id, u.email, u.full_name, u.password, u.profile_id, p.description, c.company_name FROM user u INNER JOIN company c ON c.company_id = u.company_id INNER JOIN profile p ON p.profile_id = u.profile_id WHERE u.email = %s',
            user['email']).fetchone()

        returnUser = None
        if row:
            returnUser = {
                'id': row['user_id'],
                'email': row['email'],
                'full_name': row['full_name'],
                'password': row['password'],
                'profile': {
                    'id': row['profile_id'],
                    'description': row['description']
                },
                'status': {
                    'id': row['user_status_id']
                },
                'company': {
                    'name': row['company_name']
                }
            }

        return returnUser

    def get_by_email_and_password(self, user):
        row = self.execute((
                           'SELECT u.user_id, u.user_status_id, u.email, u.full_name, c.company_name FROM user u INNER JOIN company c ON c.company_id = u.company_id WHERE u.email = %s AND u.password = %s'),
                           user['email'], user['password']).fetchone()

        returnUser = None
        if row:
            returnUser = {
                'id': row['user_id'],
                'email': row['email'],
                'full_name': row['full_name'],
                'status': {
                    'id': row['user_status_id']
                },
                'company': {
                    'name': row['company_name']
                }
            }

        return returnUser

    def get_by_valid_token(self, token):
        row = self.execute(
            'SELECT u.user_id, u.user_status_id, u.email, u.full_name, u.company_id, c.company_name, u.profile_id, p.description as \'profile_description\' FROM user u INNER JOIN token t ON t.user_id = u.user_id INNER JOIN company c ON c.company_id = u.company_id INNER JOIN profile p ON p.profile_id = u.profile_id WHERE t.code = %s AND t.is_active = 1 AND t.expiring_date > NOW()',
            token['code']).fetchone()

        returnUser = None
        if row:
            returnUser = {
                'id': row['user_id'],
                'email': row['email'],
                'full_name': row['full_name'],
                'profile': {
                    'id': row['profile_id'],
                    'description': row['profile_description']
                },
                'status': {
                    'id': row['user_status_id']
                },
                'company': {
                    'id': row['company_id'],
                    'name': row['company_name']
                }
            }
        return returnUser

    def get_by_token(self, token):
        row = self.execute(
            'SELECT u.user_id, u.user_status_id, u.email, u.full_name, u.company_id FROM user u INNER JOIN token t ON t.user_id = u.user_id WHERE t.code = %s',
            token['code']).fetchone()

        returnUser = None
        if row:
            returnUser = {
                'id': row['user_id'],
                'email': row['email'],
                'full_name': row['full_name'],
                'status': {
                    'id': row['user_status_id']
                },
                'company': {
                    'id': row['company_id']
                }
            }
        return returnUser

    def insert(self, user):
        return self.execute(
            'INSERT INTO user(user_status_id, company_id, profile_id, full_name, email, date_created, supervisor_id) VALUES(%s, %s, %s, %s, %s, NOW(), %s); ',
            user['status']['id'], user['company']['id'], user['profile']['id'], user['full_name'], user['email'],
            user['supervisor']['id']).lastrowid

    def list_all(self):
        rows = self.execute('SELECT u.user_id, u.full_name, u.email, u.password FROM user u').fetchall()

        returnUsers = None
        if rows:
            returnUsers = []
            for col in rows:
                user = {
                    'id': col['user_id'],
                    'email': col['email'],
                    'full_name': col['full_name'],
                    'password': col['password']
                }
                returnUsers.append(user)

        return returnUsers

    def list_by_company(self, company):
        rows = self.execute(
            "SELECT u.user_id, u.full_name, u.email, p.description, s.user_status_id, s.description as 'status_description', u.supervisor_id, su.full_name AS 'supervisor' FROM user u INNER JOIN profile p ON p.profile_id = u.profile_id INNER JOIN user_status s ON s.user_status_id = u.user_status_id LEFT JOIN user su ON su.user_id = u.supervisor_id WHERE u.company_id = %s ORDER BY u.full_name",
            company['id']).fetchall()

        returnUsers = None
        if rows:
            returnUsers = []
            for row in rows:
                supervisor = None
                if (row['supervisor_id']):
                    supervisor = {
                        'id': row['supervisor_id'],
                        'full_name': row['supervisor']
                    }

                user = {
                    'id': row['user_id'],
                    'email': row['email'],
                    'full_name': row['full_name'],
                    'profile': {
                        'description': row['description']
                    },
                    'status': {
                        'id': row['user_status_id'],
                        'description': row['status_description']
                    },
                    'supervisor': supervisor
                }
                returnUsers.append(user)

        return returnUsers

    def update(self, user):
        self.execute(
            'UPDATE user SET user_status_id = %s, profile_id = %s, full_name = %s, email = %s, supervisor_id = %s WHERE user_id = %s',
            user['status']['id'], user['profile']['id'], user['full_name'], user['email'], user['supervisor']['id'],
            user['id'])

    def update_password(self, user):
        self.execute('UPDATE user SET password = %s WHERE user_id = %s', user['password'], user['id'])

    def update_status(self, user):
        self.execute('UPDATE user SET user_status_id = %s WHERE user_id = %s', user['status']['id'], user['id'])
