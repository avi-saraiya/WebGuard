.PHONY: help install test lint format build dev-backend

help:
	@echo "Targets: install, test, lint, format, build, dev-backend"

install:
	cd backend && uv sync
	cd extension && npm ci

test:
	cd backend && uv run pytest
	cd extension && npm test

lint:
	cd backend && uv run ruff check . && uv run ruff format --check . && uv run mypy app
	cd extension && npm run lint && npm run typecheck

format:
	cd backend && uv run ruff format . && uv run ruff check --fix .

build:
	cd extension && npm run build

dev-backend:
	cd backend && uv run uvicorn app.main:app --reload --port 8000
