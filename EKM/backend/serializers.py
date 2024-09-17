import serpy

class AppSerializer(serpy.Serializer):
    id = serpy.IntField()
    application_name = serpy.Field()
    application_api_token = serpy.Field()
    application_created_date = serpy.Field()
    application_modified_date = serpy.Field()
    is_active = serpy.BoolField()

class KeySerializer(serpy.Serializer):
    id = serpy.IntField()
    key_secret = serpy.Field()
    key_app_id = AppSerializer()
    key_public = serpy.Field()
    key_private = serpy.Field()
    key_created_date = serpy.Field()
    is_active = serpy.BoolField()

class AlgorithmSerializer(serpy.Serializer):
    id = serpy.IntField()
    algorithm_name = serpy.Field()
    algorithm_created_by_id = serpy.Field()
    algorithm_modified_by_id = serpy.Field()
    algorithm_created_by_date = serpy.Field()
    algorithm_modified_by_date = serpy.Field()
    is_active = serpy.BoolField()

class ActivitySerializer(serpy.Serializer):
    id = serpy.IntField()
    activities_app_id = serpy.IntField()
    activities_type = serpy.Field()
    activities_data_name = serpy.Field()
    activities_status = serpy.Field()
    activities_created_date = serpy.Field()