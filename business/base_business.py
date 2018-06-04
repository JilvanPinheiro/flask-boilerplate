from context import Context


# -*- coding: utf-8 -*-
class BaseBusiness():
    context = None

    def __init__(self, context=None):
        if context:
            self.context = Context()

            if self.context.cockpit_connection:
                self.context.cockpit_inherited_connection = True
                self.context.cockpit_connection = self.context.cockpit_connection

            if self.context.cockpit_nosql_connection:
                self.context.cockpit_nosql_inherited_connection = True
                self.context.cockpit_nosql_connection = self.context.cockpit_nosql_connection


    def initialize_context(self):
        if not self.context:
            self.context = Context()

    def close_and_commit_context(self):
        self.context.commit_cockpit()
        self.context.commit_cockpit_nosql()
        self.context.close_cockpit()
        self.context.close_cockpit_nosql()
