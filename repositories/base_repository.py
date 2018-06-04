# -*- coding: utf-8 -*-
import re
import math


class BaseRepository():
    context = None

    def __init__(self, context):
        self.context = context


class CockpitRepository(BaseRepository):
    def execute(self, sql, *args):
        cursor = self.context.cockpit_connection.cursor(dictionary=True, buffered=True)
        cursor.execute(sql, args)
        return cursor


class CockpitNoSqlRepository(BaseRepository):
    def aggregate(self, collection, stages):
        collection_obj = self.context.cockpit_nosql_connection[collection]
        return_obj = collection_obj.aggregate(stages)

        return return_obj

    def find(self, collection, document, projection=None, pagination=None):
        collection_obj = self.context.cockpit_nosql_connection[collection]

        if not pagination:
            return_obj = collection_obj.find(document, projection)
        else:
            items = list(collection_obj.find(document, projection).skip(
                ((int(pagination['page']) - 1) * int(pagination['page_size']))).limit(int(pagination['page_size'])))
            total_items = collection_obj.count(document)

            # calculate total pages
            page = int(pagination['page'])
            total_pages = math.ceil(float(total_items) / float(pagination['page_size']))

            return_obj = {
                'items': items,
                'total_pages': total_pages,
                'items_count': len(items),
                'page_size': pagination['page_size'],
                'page': page,
                'first_page': (page == 1),
                'last_page': (page == total_pages),
                'total_items': total_items
            }

        return return_obj

    def find_one(self, collection, document, projection=None):
        collection_obj = self.context.cockpit_nosql_connection[collection]
        return_obj = collection_obj.find_one(document, projection)

        return return_obj

    def insert_one(self, collection, document):
        collection_obj = self.context.cockpit_nosql_connection[collection]
        return_obj = collection_obj.insert_one(document).inserted_id

        return return_obj

    def update_one(self, collection, where, set):
        collection_obj = self.context.cockpit_nosql_connection[collection]
        return_obj = collection_obj.update_one(where, set)

        return return_obj

    def get_like_expression(self, value):
        regx = re.compile(".*" + value + ".*", re.IGNORECASE)

        return regx
