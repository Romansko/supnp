# For manual usage, use "source venv/bin/activate" after venv is set.

ENTITIES := CA UCA CP SD

# Fully automate venv installation & artifacts generation using libupnp sample.
.PHONY: sample
sample: clear | venv
	./venv/bin/python3 ./device_enrollment.py ../upnp/sample/web/tvdevicedesc.xml
	@echo [*] Artifacts: 
	@tree $(ENTITIES)

# Create python venv with its requirements.
venv:
	python3 -m venv venv
	venv/bin/pip install -r requirements.txt

# Clean venv and artifacts.
.PHONY: clean
clean: clear
	rm -rf venv __pycache__


# Clean artifacts only.
.PHONY: clear
clear:
	clear
	rm -rf $(ENTITIES)

