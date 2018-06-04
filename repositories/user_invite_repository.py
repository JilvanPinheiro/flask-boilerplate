# -*- coding: utf-8 -*-
from constants import *
from base_repository import CockpitRepository
import pyodbc


class UserInviteRepository(CockpitRepository):
    def get_last_invite(self, invite):
        row = self.execute(
            "SELECT ui.status_id, ui.date_created, CASE WHEN ui.expiring_date < NOW() THEN 1 ELSE 0 END AS 'has_expired', ui.user_id_created, uc.full_name FROM user_invite ui INNER JOIN user uc ON uc.user_id = ui.user_id_created WHERE ui.user_id = %s ORDER BY ui.date_created DESC LIMIT 1",
            invite['id']).fetchone()

        returnInvite = None
        if row:
            returnInvite = {
                'date_created': row['date_created'],
                'status': {
                    'id': row['status_id']
                },
                'has_expired': row['has_expired'],
                'user_created': {
                    'id': row['user_id_created'],
                    'full_name': row['full_name']
                }
            }

        return returnInvite

    def get_valid_invite(self, invite):
        row = self.execute(
            'SELECT ui.user_invite_id, ui.status_id, ui.expiring_date, ui.date_redeemed FROM user_invite ui WHERE ui.user_id = %s AND ui.access_code = %s AND ui.status_id = %s AND ui.expiring_date > NOW()',
            invite['user']['id'], invite['access_code'], Status.ACTIVE, ).fetchone()

        returnInvite = None
        if row:
            returnInvite = {
                'id': row['user_invite_id'],
                'status': {
                    'id': row['status_id']
                },
                'expiring_date': row['expiring_date'],
                'date_redeemed': row['date_redeemed']
            }

        return returnInvite

    def insert(self, user_invite):
        return self.execute(
            'INSERT INTO user_invite(user_id, access_code, status_id, expiring_date, date_created, user_id_created) VALUES(%s, %s, %s, DATE_ADD(NOW(), INTERVAL 30 DAY), NOW(), %s); ',
            user_invite['user']['id'], user_invite['access_code'], user_invite['status']['id'],
            user_invite['user_created']['id']).lastrowid

    def redeem(self, invite):
        self.execute('UPDATE user_invite SET date_redeemed = NOW() WHERE user_invite_id = %s', invite['id'])

    def update_status(self, invite):
        self.execute('UPDATE user_invite SET status_id = %s WHERE user_invite_id = %s', invite['status']['id'],
                     invite['id'])
