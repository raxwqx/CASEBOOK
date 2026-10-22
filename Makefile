.PHONY: test lint check build clean

test:
	python -m unittest discover -s tests -v

lint:
	python -m compileall -q src tests

check: lint test

build:
	python -m pip install --upgrade build
	python -m build

clean:
	rm -rf build dist *.egg-info .pytest_cache .coverage htmlcov
