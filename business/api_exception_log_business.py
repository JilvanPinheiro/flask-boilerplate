# -*- coding: utf-8 -*-
from base_business import BaseBusiness
from repositories.api_exception_log_repository import ApiExceptionLogRepository


class ApiExceptionLogBusiness(BaseBusiness):
    def insert(self, log):
        # prepare context
        self.initialize_context()
        self.context.connect_cockpit_nosql()

        # insert log
        logRep = ApiExceptionLogRepository(self.context)
        logRep.insert(log)

        # finalize context
        self.close_and_commit_context()
