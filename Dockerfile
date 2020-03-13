FROM mhoush/psycopg2

WORKDIR /app
COPY . /app

RUN pip install --upgrade pip
RUN pip install --upgrade /app

CMD ["/usr/bin/make", "run-example"]
