# -*- coding: utf-8 -*-
from base_repository import CockpitRepository
import pyodbc


class TokenRepository(CockpitRepository):
    def deactivate_all(self, user):
        self.execute('UPDATE token SET is_active = 0 WHERE user_id = %s AND is_active = 1 AND expiring_date > NOW()',
                     user['id'])

    def get_by_code_email(self, token):
        row = self.execute(
            'SELECT t.is_active FROM token t INNER JOIN user u ON u.user_id = t.user_id WHERE t.code = %s AND u.email = %s',
            token['code'], token['user']['email']).fetchone()

        returnToken = None
        if row:
            returnToken = {
                'is_active': row['is_active']
            }

        return returnToken

    def insert(self, token):
        self.execute(
            'INSERT INTO token(user_id, is_active, code, expiring_date, date_created) VALUES(%s, 1, %s, DATE_ADD(NOW(), INTERVAL 7 DAY), NOW())',
            token['user']['id'], token['code'])
