
IMAGE_NAME := "nifcloud/ansible-role-nifcloud"
build:
	docker build -t ${IMAGE_NAME} .

test:
	make build
	docker run -u $(shell id -u):$(shell id -g) --workdir /work/library --rm -ti -v $(PWD):/work ${IMAGE_NAME}
