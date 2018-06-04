# -*- coding: utf-8 -*-
from base_repository import CockpitNoSqlRepository
import pyodbc


class ApiExceptionLogRepository(CockpitNoSqlRepository):
    def insert(self, api_exception):
        return self.insert_one('api_exception_log', api_exception)
