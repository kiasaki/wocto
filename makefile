APP_NAME=wocto
APP_PORT=8006
SSH_REMOTE=ubuntu@99.79.120.13
LC_ALL=C

dev:
	@which reflex>/dev/null || go install github.com/cespare/reflex@latest
	reflex -s -d none -r '.(go|php)$$' -- make run

run:
	go run main.go

ssh:
	ssh $(SSH_REMOTE)

deploy-build:
	GOOS=linux go build -ldflags "-s -w -extldflags=-static" -installsuffix cgo -tags sqlite_omit_load_extension -o server *.go

deploy: deploy-build
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


