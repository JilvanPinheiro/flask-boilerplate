# -*- coding: utf-8 -*-
from base_business import BaseBusiness
from repositories.api_request_log_repository import ApiRequestLogRepository


class ApiRequestLogBusiness(BaseBusiness):
    def insert(self, log):
        # prepare context
        self.initialize_context()
        self.context.connect_cockpit_nosql()

        # insert log
        logRep = ApiRequestLogRepository(self.context)
        logRep.insert(log)

        # finalize context
        self.close_and_commit_context()
