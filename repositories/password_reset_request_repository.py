# -*- coding: utf-8 -*-
from base_repository import CockpitRepository
import pyodbc


class PasswordResetRequestRepository(CockpitRepository):
    def deactivate_all(self, user):
        self.execute('UPDATE password_reset_request SET is_active = 0 WHERE email = %s', user['email'])

    def get_valid_request(self, request):
        row = self.execute(
            'SELECT p.password_reset_request_id FROM password_reset_request p WHERE p.email = %s AND p.token = %s AND p.is_active = 1',
            request['email'], request['token']).fetchone()

        returnRequest = None
        if row:
            returnRequest = {
                'id': row['password_reset_request_id']
            }

        return returnRequest

    def insert(self, request):
        self.execute(
            'INSERT INTO password_reset_request(email, date_created, token, is_active) VALUES(%s, NOW(), %s, %s)',
            request['email'], request['token'], request['is_active'])
