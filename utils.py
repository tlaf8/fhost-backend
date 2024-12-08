from flask import request, jsonify
from flask_jwt_extended import get_jwt_identity
import os


def validate_static_access(func):
    def wrapper(*args, **kwargs):
        dirname = kwargs.get('dirname')
        identity = get_jwt_identity()

        if identity['dirname'] != dirname:
            return jsonify({"message": "Unauthorized access"}), 403

        return func(*args, **kwargs)

    return wrapper
