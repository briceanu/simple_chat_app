import redis
import os

from dotenv import load_dotenv
load_dotenv()

REDIS_HOST = os.getenv('REDIS_HOST')
REDIS_PORT = os.getenv('REDIS_PORT')


redis_client = redis.Redis(host=REDIS_HOST,port=REDIS_PORT,db=1,decode_responses=True)

