FROM python:3.8-slim

WORKDIR /app

COPY requirements.txt main.py constant.py ./

# Install required packages
RUN pip install --no-cache-dir  -r requirements.txt

# Run the python script
ENTRYPOINT [ "python3", "-u", "./main.py" ]
