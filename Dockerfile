FROM mhoush/psycopg2

RUN pip install --upgrade pip
RUN pip install --upgrade pytest
RUN pip install --upgrade pytest-cov


ADD . /app

RUN pip install --upgrade /app

WORKDIR /app

CMD ["/usr/bin/make", "run-example"]
