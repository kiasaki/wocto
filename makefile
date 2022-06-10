APP_NAME=wocto
APP_PORT=8006
SSH_REMOTE=ubuntu@99.79.120.13
LC_ALL=C

dev:
	@which reflex>/dev/null || go install github.com/cespare/reflex@latest
	reflex -s -d none -r '.(go|php)$$' -- make run

run:
	go run main.go

db:
	psql -d $(APP_NAME)

dbsetup:
	psql -c "CREATE ROLE admin WITH SUPERUSER LOGIN PASSWORD 'admin';" || true
	psql -c "CREATE DATABASE $(APP_NAME) WITH OWNER admin;" || true
	psql -d $(APP_NAME) < db.sql || true

dbreset:
	psql -c "DROP DATABASE $(APP_NAME);" || true
	psql -c "CREATE DATABASE $(APP_NAME) WITH OWNER admin;" || true
	psql -d $(APP_NAME) < db.sql || true

deploy:
	git push https://git.heroku.com/wocto.git main

ssh:
	ssh $(SSH_REMOTE)

deploy-build:
	GOOS=linux go build -ldflags "-s -w -extldflags=-static" -installsuffix cgo -tags sqlite_omit_load_extension -o server *.go

deploy2: deploy-build
	scp server $(SSH_REMOTE):/tmp/dtmpl
	ssh $(SSH_REMOTE) "mv /tmp/dtmpl /home/ubuntu/apps/$(APP_NAME)/server"
	ssh $(SSH_REMOTE) "sudo systemctl restart $(APP_NAME)"

deploy-setup:
	scp support/nginx.conf $(SSH_REMOTE):/tmp/dtmpl
	ssh $(SSH_REMOTE) "sudo mv /tmp/dtmpl /etc/nginx/sites-enabled/$(APP_NAME).conf"
	ssh $(SSH_REMOTE) "sudo systemctl restart nginx"
	env APP_NAME=$(APP_NAME) APP_PORT=$(APP_PORT) sh -c "cat support/app.service | envsubst > /tmp/dtmpl"
	scp /tmp/dtmpl $(SSH_REMOTE):/tmp/dtmpl
	ssh $(SSH_REMOTE) "sudo mv /tmp/dtmpl /etc/systemd/system/$(APP_NAME).service"
	ssh $(SSH_REMOTE) "sudo systemctl daemon-reload"
	ssh $(SSH_REMOTE) "sudo systemctl enable $(APP_NAME)"
	ssh $(SSH_REMOTE) "mkdir -p /home/ubuntu/apps/$(APP_NAME)/data/{db,files}"
	ssh $(SSH_REMOTE) "rm -rf /etc/nginx/sites-enabled/default"


