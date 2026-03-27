from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="agsec",
    version="0.1.1",
    author="Riyandhiman",
    author_email="noreply@example.com",
    description="AI Agent Action Firewall core SDK",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/agsec",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=[
        "PyYAML>=6.0",
    ],
    extras_require={
        "dev": [
            "pre-commit>=3.0",
            "black>=24.0",
            "isort>=5.0",
            "flake8>=7.0",
            "pytest>=6.0",
            "build>=1.0",
            "twine>=4.0",
        ],
    },
)
