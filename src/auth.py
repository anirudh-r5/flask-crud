import jwt
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import request, abort, g

def generate_jwt_token(user_id, secret_key):
	expiration = datetime.now(timezone.utc) + timedelta(hours=1)
	payload = {
		"user_id": user_id,
		"exp": expiration
	}
	token = jwt.encode(payload, secret_key, algorithm="HS256")
	return token

def token_required(secret_key):
	def decorator(f):
		@wraps(f)
		def decorated(*args, **kwargs):
			auth_header = request.headers.get("Authorization", None)
			if not auth_header:
				abort(401, description="Missing Authorization header")

			parts = auth_header.split()
			if len(parts) != 2 or parts[0].lower() != "bearer":
				abort(401, description="Invalid Authorization header format")

			token = parts[1]
			try:
				decoded = jwt.decode(token, secret_key, algorithms=["HS256"])
				user_id = decoded.get("user_id")
				if not user_id:
					abort(401, description="Invalid token payload")
				g.current_user_id = user_id

			except jwt.ExpiredSignatureError:
				abort(401, description="Token has expired")
			except jwt.InvalidTokenError:
				abort(401, description="Invalid token")

			return f(*args, **kwargs)
		return decorated
	return decorator
