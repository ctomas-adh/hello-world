USERNAME_PATTERN = '[A-Za-z][A-Za-z0-9_]{7,29}'
PASSWORD_PATTERN = '[A-Za-z0-9@#$%^&+=_\-\!\?\.\/]{8,32}'
BASIC_AUTH_PATTERN = r'^({0})/({1})$'.format(USERNAME_PATTERN, PASSWORD_PATTERN)
TOKEN_AUTH_PATTERN = r'^[A-Za-z0-9\-\._~\+\/]+=*$'