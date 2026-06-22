SHELL = bash
VERSION ?= 3.2.0

.PHONY: test
test:
	./tests/test-checksec.sh

.PHONY: coverage
coverage:
	go test ./pkg/... -count=1 -coverpkg=./pkg/... -coverprofile=coverage.out -covermode=count
	go tool cover -func=coverage.out

.PHONY: build-image
build-image:
	docker build -t slimm609/checksec .

.PHONY: build
build:
	goreleaser build --snapshot --clean

# Cut a release by pushing a tag. The release workflow
# (.github/workflows/release.yml) then builds, signs (keyless cosign), and
# publishes the GitHub release. Run a local dry run first with `make build`.
.PHONY: release
release:
	git tag $(VERSION) -m "release of $(VERSION)"
	git push origin $(VERSION)
