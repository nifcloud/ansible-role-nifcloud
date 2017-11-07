
IMAGE_NAME := "nifcloud/ansible-role-nifcloud"

build:
	docker build -t ${IMAGE_NAME} .
test:
	make build
	docker run --workdir /work/library --rm -ti -v $(PWD):/work ${IMAGE_NAME} bash -c " \
          nosetests --no-byte-compile --with-coverage && \
          coverage report --include=./nifcloud*.py"
