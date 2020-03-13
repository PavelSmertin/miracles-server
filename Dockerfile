FROM mhoush/psycopg2

ADD . /app

RUN pip install --upgrade /app  \
	pip \
    pytest \
    pytest-cov

WORKDIR /app

CMD ["/usr/bin/make", "run-example"]
