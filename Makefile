.PHONY: help up down restart logs ps bootstrap-creds backend-build backend-test backend-vet frontend-build frontend-dev scale clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

up: ## Build and start the whole stack
	docker compose up -d --build

down: ## Stop the stack
	docker compose down

restart: ## Restart the stack
	docker compose restart

logs: ## Tail logs
	docker compose logs -f

ps: ## Show running services
	docker compose ps

bootstrap-creds: ## Print the first-admin credentials (printed on first boot)
	docker compose logs app

scale: ## Validate statelessness by running N app replicas (make scale N=3)
	docker compose up -d --scale app=$(or $(N),3) --no-recreate

backend-build: ## Compile the backend
	cd backend && go build ./...

backend-vet: ## Vet the backend
	cd backend && go vet ./...

backend-test: ## Run backend unit tests
	cd backend && go test ./...

backend-itest: ## Run backend integration tests (needs Docker for testcontainers)
	cd backend && go test -tags=integration ./...

frontend-build: ## Type-check + build the frontend
	cd frontend && npm run build

frontend-dev: ## Run the frontend dev server (proxies to backend:8080)
	cd frontend && npm run dev

clean: ## Remove volumes (DESTROYS DATA)
	docker compose down -v
