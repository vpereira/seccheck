build:
	docker build -t $(USER)/seccheck .
run:
	 docker run -ti -v "$(PWD):/seccheck" $(USER)/seccheck  /bin/bash
