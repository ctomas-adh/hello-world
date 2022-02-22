import logging
import os
import sys
import re
import base64
import requests
import constant
from requests.structures import CaseInsensitiveDict


def basicAuthHeader(auth_string):
  """ Build the basic authentication header of HTTP request.
  The authorization string matches the pattern 'username/password'.
  : param auth_string: the authentication string containing the 'username/password' credentials.
  : return: the 'Basic username/password' authorization header.
  """
  result = re.search(constant.BASIC_AUTH_PATTERN, auth_string)
  if result.groups() and len(result.groups()) == 2:
    username = result.group(1)
    password = result.group(2)
    base64_auth = base64.b64encode('{0}:{1}'.format(username, password).encode('ascii')).decode('ascii')
    auth_header = 'Basic {0}'.format(base64_auth)
  return auth_header


def bearerAuthHeader(auth_string):
  """ Build the bearer token authentication header of HTTP request.
  : param auth_string: the authentication string containing the OAuth token.
  : return: the 'Bearer token' authorization header.
  """
  token = auth_string
  auth_header = 'Bearer {0}'.format(token)
  return auth_header


def buildAuthHeader(auth_string):
  """ Build the authentication header of HTTP request.
  If the authorization string matches the pattern 'username/password', build a Basic Auth authorization header.
  If the authorization string is a token, build a Bearer authorization header.
  : param auth_string: the authentication string (token or username/password credentials).
  : return: the authentication header (either Basic username/password or Bearer token).
  """
  auth_header = ""
  if re.match(constant.BASIC_AUTH_PATTERN, auth_string):
    logging.debug('Basic authentication.')
    auth_header = basicAuthHeader(auth_string)
  elif re.match(constant.TOKEN_AUTH_PATTERN, auth_string):
    logging.debug('Bearer token authentication.')
    auth_header = bearerAuthHeader(auth_string)
  else:
    sys.exit('Not a valid authentication string')
  return auth_header


def readInputs():
  """
  Read input values from environment variables.
  : return: A tuple with the following values: 
            method, url, timeout, content_type, data, auth_string, fake_response, ignore_status
  """
  method = os.environ.get('INPUT_METHOD')
  if not method:
    sys.exit('A http request method (GET, POST, PUT, PATCH, DELETE) is required')
  logging.info('method: %s', method)

  url = os.environ.get('INPUT_URL')
  if not url:
    sys.exit('A URL to send API requests is required')
  logging.info('url: %s', url)

  timeout = int(os.environ.get('INPUT_TIMEOUT')) if 'INPUT_TIMEOUT' in os.environ else None
  if not timeout:
    sys.exit('A request timeout is required')
  logging.info('timeout: %s', timeout)

  content_type = os.environ.get('INPUT_CONTENT_TYPE')
  logging.info('content_type: %s', content_type)

  data = os.environ.get('INPUT_DATA')
  logging.info('data: %s', data)

  auth_string = os.environ.get('INPUT_AUTH_STRING')
  logging.info('auth_string: %s', auth_string)

  fake_response = os.environ.get('INPUT_FAKE_RESPONSE')
  logging.info('fake_response: %s', fake_response)

  ignore_status = os.environ.get('INPUT_IGNORE_STATUS')
  logging.info('ignore_status: %s', ignore_status)

  return method, url, timeout, content_type, data, auth_string, fake_response, ignore_status


def sendRequest(method, url, timeout, content_type, data, auth_string, fake_response, ignore_status):
  """
  Send a HTTP request to the orchestration API.
  : param method: (GET, POST, PUT, PATCH, DELETE)
  : param url: the request URL to the orchestration API
  : paramtimeout: timeout in seconds to wait for the response
  : param content_type: the type of the body content (application/json, text/html, text/plain, application/xml...)
  : param data: the data in the body content
  : param auth_string: a token or username/password credentials
  : return: status code of the response
  """
  headers = CaseInsensitiveDict()
  if content_type:
    headers['Content-Type'] = content_type
  if auth_string:
    logging.debug('Build authentication header')
    auth_header = buildAuthHeader(auth_string)
    headers['Authorization'] = auth_header
  
  response = requests.request(method=method, url=url, timeout=timeout, headers=headers, data=data)
  
  return response.status_code


def main(): 
  """
  Main entrypoint.
  """
  # Configure logging
  logging.basicConfig(
      format='%(asctime)s | %(levelname)-6s | %(message)s', 
      datefmt='%d-%b-%y %H:%M:%S', 
      level=logging.DEBUG)

  # Read inputs from environment variables
  method, url, timeout, content_type, data, auth_string, fake_response, ignore_status = readInputs()
  
  # Send the request to the API
  response_status = sendRequest(method, url, timeout, content_type, data, auth_string, fake_response, ignore_status)
  logging.info("Response status code: %d", response_status)
  
  # Set outputs
  print("::set-output name=response_status::" + str(response_status))


if __name__ == '__main__':
  main()
