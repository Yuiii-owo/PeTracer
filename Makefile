.PHONY: init test selftest e2e clean

init:
	python3 -m petracer init

test:
	python3 -m unittest discover -s tests -v

selftest:
	python3 -m petracer selftest

e2e:
	PETRACER_E2E=1 python3 -m unittest tests.test_e2e -v

clean:
	rm -rf build petracer-out demo analysis .pytest_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
