# -*- coding: utf-8 -*-
from config import CockpitDb
from config import CockpitNoSqlDb
from config import MothershipNoSqlDb
from pymongo import MongoClient
import mysql.connector


class Context:
    # connections
    cockpit_connection = None
    cockpit_nosql_connection = None
    cockpit_nosql_client = None
    mothership_connection = None
    mothership_client = None

    # inheritance flags
    cockpit_inherited_connection = False
    cockpit_nosql_inherited_connection = False
    mothership_inherited_connection = False

    def connect_cockpit(self):
        if not self.cockpit_inherited_connection:
            self.cockpit_connection = mysql.connector.connect(user=CockpitDb.USER_ID, password=CockpitDb.PASSWORD,
                                                              host=CockpitDb.HOST, database=CockpitDb.DATABASE,
                                                              port=int(CockpitDb.PORT), autocommit=False)

    def connect_cockpit_nosql(self):
        if not self.cockpit_nosql_inherited_connection:
            self.cockpit_nosql_client = MongoClient(CockpitNoSqlDb.HOST, int(CockpitNoSqlDb.PORT))
            self.cockpit_nosql_connection = self.cockpit_nosql_client[CockpitNoSqlDb.DATABASE]
            if CockpitNoSqlDb.USER_ID and len(CockpitNoSqlDb.USER_ID) > 0:
                self.cockpit_nosql_connection.authenticate(CockpitNoSqlDb.USER_ID, CockpitNoSqlDb.PASSWORD)

    def commit_cockpit(self):
        if not self.cockpit_inherited_connection and self.cockpit_connection:
            self.cockpit_connection.commit()

    def commit_cockpit_nosql(self):
        # nothing to do. nosql database
        return True

    def close_cockpit(self):
        if not self.cockpit_inherited_connection and self.cockpit_connection:
            self.cockpit_connection.close()

    def close_cockpit_nosql(self):
        if not self.cockpit_nosql_inherited_connection and self.cockpit_nosql_client:
            self.cockpit_nosql_client.close()
