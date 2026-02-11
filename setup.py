from setuptools import setup, find_packages

setup(
    name="cyber-incident-response",
    version="0.1.0",
    description="Autonomous Cyber Incident Response Tool for Banking",
    author="Aditya",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    python_requires=">=3.9",
    install_requires=[
        line.strip()
        for line in open("requirements.txt").readlines()
        if line.strip() and not line.startswith("#")
    ],
    entry_points={
        "console_scripts": [
            "cir-server=cir.api.server:main",
            "cir-cli=cir.cli.main:main",
        ],
    },
)
