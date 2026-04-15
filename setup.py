from setuptools import setup, find_packages

with open("README.md", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="pipeline_check",
    version="0.1.0",
    description="CI/CD Security Posture Scanner (AWS, Terraform, GitHub Actions) — scores pipelines against OWASP Top 10 CI/CD Risks",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Daniel Martin",
    python_requires=">=3.10",
    packages=find_packages(),
    install_requires=[
        "boto3>=1.34.0",
        "click>=8.1.0",
        "rich>=13.0.0",
        "PyYAML>=6.0",
    ],
    entry_points={
        "console_scripts": [
            "pipeline_check=pipeline_check.cli:scan",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "Programming Language :: Python :: 3.10",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
