
IMAGE_NAME := "nifcloud/ansible-role-nifcloud"

build:
	docker build -t ${IMAGE_NAME} .
test:
	make build
	docker run --workdir /work/ --rm -ti -v $(PWD):/work ${IMAGE_NAME} bash -c " \
          coverage run --source=library -m pytest library/tests/"
