# -*- coding: utf-8 -*-
from base_repository import CockpitRepository
import pyodbc


class PermissionRepository(CockpitRepository):
    def get(self, permission):
        row = self.execute('SELECT p.permission_id FROM permission p WHERE p.user_id = %s AND p.action = %s',
                           permission['user']['id'], permission['action']).fetchone()

        returnPermission = None
        if row:
            returnPermission = {
                'id': row['permission_id']
            }

        return returnPermission

    def list(self, user):
        rows = self.execute('SELECT p.action FROM permission p WHERE p.user_id = %s', user['id']).fetchall()

        returnPermissions = None
        if rows:
            returnPermissions = []
            for row in rows:
                returnPermission = {
                    'action': row['action']
                }
                returnPermissions.append(returnPermission)

        return returnPermissions

    def insert(self, permission):
        return self.execute('INSERT INTO permission(user_id, action) VALUES(%s, %s); ', permission['user']['id'],
                            permission['action']).lastrowid

    def delete_all(self, user):
        self.execute('DELETE FROM permission WHERE user_id = %s', user['id'])
