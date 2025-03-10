from setuptools import setup, find_packages

setup(
    name="shadowscan",
    version="0.1",
    packages=find_packages(),
    install_requires=[],
    entry_points={
        "console_scripts": [
            "shadowscan=shadowscan.scanner:main"
        ]
    },
)

