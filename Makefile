install:
	uv sync

clean:
	rm -rf build dist
	find . -type d \( \
		-name .pytest_cache -o \
		-name .mypy_cache -o \
		-name __pycache__ -o \
		-name '*.egg-info' \
	\) -prune -exec rm -rf \{\} \;

uninstall:
	uv pip uninstall -q recover

mypy:
	uv run mypy src/recover/

pylint:
	uv run pylint --rcfile pylintrc src/recover/
